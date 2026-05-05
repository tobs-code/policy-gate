use crate::config;
use crate::fsm;
use crate::profile::FirewallProfile;
use crate::session;
use crate::types::{
    AdvisoryTag, AuditEntry, BlockReason, ChannelDecision, ChannelId, ChannelResult, MatchedIntent,
    Verdict, VerdictKind,
};
use std::sync::OnceLock;
use subtle::ConstantTimeEq;

// Mirrors the napi-layer guard (SA-021) for direct firewall-core callers.
// evaluate() and evaluate_raw() both check this before running any channel.
// Fail-closed: if init() was never called or failed -> Block verdict returned.
static INIT_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

// Race-to-init protection via BUILD-TIME token. The init token is baked into
// the binary at compile time via env!("POLICY_GATE_INIT_TOKEN"). There is NO
// runtime default - if the env var is not set at build time, compilation fails.
const INIT_TOKEN: &str = env!("POLICY_GATE_INIT_TOKEN");

// Loaded and managed via TenantRegistry (Pillar 5).
// Keys are Tenant IDs; values are their specific configurations.
static TENANT_REGISTRY: OnceLock<std::sync::RwLock<std::collections::HashMap<String, config::FirewallConfig>>> = OnceLock::new();

/// Internal startup path for the firewall safety boundary.
///
/// This module owns the init state and the OC-01 fail-closed guard helpers.
/// Behavioural requirements:
/// - initialization is cached via `OnceLock`
/// - production initialization requires the build-time token
/// - config and profile state are loaded exactly once
/// - callers that evaluate before successful init receive a synthetic Block verdict
pub fn init_with_token(
    token: &str,
    profile: FirewallProfile,
) -> Result<(), crate::FirewallInitError> {
    // SA-081: Constant-time comparison to prevent timing attacks on token verification
    if !bool::from(token.as_bytes().ct_eq(INIT_TOKEN.as_bytes())) {
        return Err(crate::FirewallInitError::UnauthorizedInit(
            "Init token mismatch - possible race-to-init attack or misconfiguration. \
             Ensure POLICY_GATE_INIT_TOKEN was set at build time."
                .into(),
        ));
    }

    init_with_profile_internal(profile, None)
}

/// Development and test initialization path without the build-time token.
///
/// This exists for local test harnesses and compatibility with integration
/// tests. Production callers should prefer `init_with_token()`.
pub fn init() -> Result<(), crate::FirewallInitError> {
    init_with_profile_internal(FirewallProfile::Default, None)
}

/// Deprecated compatibility path retained for older callers.
pub fn init_with_profile(profile: FirewallProfile) -> Result<(), crate::FirewallInitError> {
    init_with_profile_internal(profile, None)
}

/// Explicit initialization with a pre-loaded configuration.
/// 
/// This is the preferred path for WASM targets and environments where 
/// configuration is pushed from a control plane instead of disk.
pub fn init_with_config(
    token: &str,
    config: config::FirewallConfig,
) -> Result<(), crate::FirewallInitError> {
    // SA-081: Constant-time comparison to prevent timing attacks on token verification
    if !bool::from(token.as_bytes().ct_eq(INIT_TOKEN.as_bytes())) {
        return Err(crate::FirewallInitError::UnauthorizedInit(
            "Init token mismatch".into(),
        ));
    }

    init_with_profile_internal(FirewallProfile::Default, Some(config))
}

fn init_with_profile_internal(
    profile: FirewallProfile,
    injected_config: Option<config::FirewallConfig>,
) -> Result<(), crate::FirewallInitError> {
    // Validate custom regex before fixing init state so invalid profiles fail cleanly.
    if let Some((id, regex, _intent)) = profile.custom_pattern() {
        regex::Regex::new(regex).map_err(|e| {
            crate::FirewallInitError::PatternCompileFailure(format!(
                "Custom pattern [{id}] regex compile failure: {e}"
            ))
        })?;
    }

    let registry = TENANT_REGISTRY.get_or_init(|| std::sync::RwLock::new(std::collections::HashMap::new()));
    
    // If a profile was provided but no injected_config, merge the profile's 
    // default permitted intents into the config of the 'default' tenant.
    let profile_intents = profile.permitted_intents();
    
    if let Some(cfg) = injected_config {
        if let Ok(mut lock) = registry.write() {
            let id = cfg.tenant_id.clone().unwrap_or_else(|| "default".into());
            lock.insert(id, cfg.clone());
        }
    } else {
        // Legacy/Default path: load firewall.toml as the 'default' tenant
        if let Ok(mut cfg) = config::FirewallConfig::load() {
             apply_defaults(&mut cfg, profile_intents);
             if let Ok(mut lock) = registry.write() {
                lock.insert("default".into(), cfg.clone());
            }
        } else {
            // No file config, use internal defaults + profile
            let mut cfg = config::FirewallConfig::default();
            apply_defaults(&mut cfg, profile_intents);
            if let Ok(mut lock) = registry.write() {
                lock.insert("default".into(), cfg);
            }
        }
    }

    let result = INIT_RESULT.get_or_init(|| {
        // SA-077: Initialize config watcher for the default config if it exists
        #[cfg(not(test))]
        if let Some(default_cfg) = get_config_for_tenant(None) {
            crate::config_watcher::init_config_watcher(default_cfg.clone());
            
            // Inject dynamic config before the startup self-test warms the matcher set.
            if let Some(custom) = &default_cfg.intents {
                let patterns = custom
                    .iter()
                    .map(|entry| {
                        fsm::intent_patterns::IntentPattern::new_dynamic(
                            entry.id.clone(),
                            entry.intent.clone(),
                            entry.regex.clone(),
                        )
                    })
                    .collect();
                fsm::intent_patterns::set_custom_patterns(patterns);
            }
        }

        #[cfg(feature = "semantic")]
        {
            println!("INIT: Starting Channel D (Semantic)");
            crate::semantic::ChannelD::init()
                .map_err(|e| format!("Channel D init failed: {}", e))?;
        }

        crate::audit::init_audit()?;
        session::init_session_manager();
        fsm::intent_patterns::startup_self_test().map_err(|errs| errs.join("; "))
    });

    result
        .as_ref()
        .copied()
        .map_err(|e| crate::FirewallInitError::PatternCompileFailure(e.clone()))
}

/// Initialize the firewall with multiple tenant configurations from a directory.
/// (Pillar 5: Multi-Tenant Policy Hub)
#[cfg(not(target_arch = "wasm32"))]
pub fn init_multi_tenant_registry<P: AsRef<std::path::Path>>(
    token: &str,
    dir_path: P,
) -> Result<(), crate::FirewallInitError> {
    // SA-081: Constant-time comparison to prevent timing attacks on token verification
    if !bool::from(token.as_bytes().ct_eq(INIT_TOKEN.as_bytes())) {
        return Err(crate::FirewallInitError::UnauthorizedInit("Token mismatch".into()));
    }

    let dir = dir_path.as_ref();
    if !dir.is_dir() {
        return Err(crate::FirewallInitError::PatternCompileFailure(format!(
            "{} is not a directory", dir.display()
        )));
    }

    let registry = TENANT_REGISTRY.get_or_init(|| std::sync::RwLock::new(std::collections::HashMap::new()));
    
    // CVE-FIX: Strict error handling for directory access to prevent TOCTOU (CVE-367)
    // If read_dir() fails, return error immediately instead of silently skipping
    let entries = std::fs::read_dir(dir)
        .map_err(|e| crate::FirewallInitError::PatternCompileFailure(
            format!("Cannot read directory {}: {}. Init failed (fail-closed).", dir.display(), e)
        ))?;
    
    let mut loaded_count = 0;
    for entry in entries {
        let entry = entry.map_err(|e| {
            crate::FirewallInitError::PatternCompileFailure(format!(
                "Cannot enumerate directory {}: {}. Init failed (fail-closed).",
                dir.display(),
                e
            ))
        })?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            let cfg = config::FirewallConfig::load_from_path(&path).map_err(|e| {
                crate::FirewallInitError::PatternCompileFailure(format!(
                    "Failed to load tenant config {}: {}. Init failed (fail-closed).",
                    path.display(),
                    e
                ))
            })?;
            let tenant_id = cfg
                .tenant_id
                .clone()
                .or_else(|| path.file_stem().and_then(|s| s.to_str()).map(|s| s.to_string()))
                .unwrap_or_else(|| "default".into());

            let mut lock = registry.write().map_err(|_| {
                crate::FirewallInitError::PatternCompileFailure(
                    "Tenant registry lock poisoned during init. Init failed (fail-closed).".into(),
                )
            })?;
            lock.insert(tenant_id, cfg);
            loaded_count += 1;
        }
    }
    
    // Log how many tenants were loaded (could be 0 which is acceptable for empty directories)
    eprintln!("[init] Loaded {} tenant configurations from {}", loaded_count, dir.display());

    // After loading all tenants, trigger the standard init path for common components
    init_with_profile_internal(FirewallProfile::Default, None)
} 

pub(crate) fn get_tenant_registry() -> Option<&'static std::sync::RwLock<std::collections::HashMap<String, config::FirewallConfig>>> {
    TENANT_REGISTRY.get()
}

/// Retrieve the configuration for a specific tenant.
/// If tenant_id is None, the 'default' policy is returned.
pub(crate) fn get_config_for_tenant(tenant_id: Option<&str>) -> Option<config::FirewallConfig> {
    let id = tenant_id.unwrap_or("default");
    TENANT_REGISTRY.get()
        .and_then(|lock| lock.read().ok())
        .and_then(|lock| lock.get(id).cloned())
}

/// Fallback for single-tenant callers.
pub(crate) fn get_config() -> Option<config::FirewallConfig> {
    get_config_for_tenant(None)
}

pub(crate) fn is_initialised() -> bool {
    matches!(INIT_RESULT.get(), Some(Ok(())))
}

/// Returns the permitted intents from the default tenant configuration.
/// This provides backward compatibility for callers that need the global profile view.
/// For multi-tenant deployments, prefer `get_config_for_tenant()` with explicit tenant_id.
pub fn active_profile_intents() -> Option<Vec<MatchedIntent>> {
    get_config_for_tenant(None)
        .and_then(|cfg| cfg.permitted_intents)
}

/// Synthesises the fail-closed verdict used by direct callers before successful init.
pub(crate) fn uninitialised_block(sequence: u64, now: u128) -> Verdict {
    let reason = BlockReason::MalformedInput {
        detail: "firewall not initialised - call init() at startup and check its result".into(),
    };
    let block = ChannelResult {
        channel: ChannelId::A,
        decision: ChannelDecision::Block {
            reason: reason.clone(),
        },
        elapsed_us: 0,
        similarity: None,
    };
    let block_b = ChannelResult {
        channel: ChannelId::B,
        decision: ChannelDecision::Block {
            reason: reason.clone(),
        },
        elapsed_us: 0,
        similarity: None,
    };
    Verdict {
        kind: VerdictKind::Block,
        channel_a: block,
        channel_b: block_b,
        channel_d: None,
        audit: AuditEntry::basic(
            sequence,
            VerdictKind::Block,
            Some(reason),
            String::new(),
            AdvisoryTag::None,
            None,
            None,
            None,
            None,
            now,
            now,
            0,
            None,
        ),
    }
}

/// Populates missing configuration fields with default values from the profile.
pub(crate) fn apply_defaults(cfg: &mut config::FirewallConfig, profile_intents: Option<Vec<MatchedIntent>>) {
    if cfg.permitted_intents.is_none() {
        cfg.permitted_intents = profile_intents;
    }
    if cfg.allow_anonymous_tenants.is_none() {
        // Pillar 5: Default to true for anonymous access if not explicitly disabled.
        cfg.allow_anonymous_tenants = Some(true);
    }
}
