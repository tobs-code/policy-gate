use crate::config;
use crate::fsm;
use crate::profile::FirewallProfile;
use crate::session;
use crate::types::{
    AdvisoryTag, AuditEntry, BlockReason, ChannelDecision, ChannelId, ChannelResult, MatchedIntent,
    Verdict, VerdictKind,
};
use std::sync::OnceLock;

// Mirrors the napi-layer guard (SA-021) for direct firewall-core callers.
// evaluate() and evaluate_raw() both check this before running any channel.
// Fail-closed: if init() was never called or failed -> Block verdict returned.
static INIT_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

// Race-to-init protection via BUILD-TIME token. The init token is baked into
// the binary at compile time via env!("POLICY_GATE_INIT_TOKEN"). There is NO
// runtime default - if the env var is not set at build time, compilation fails.
const INIT_TOKEN: &str = env!("POLICY_GATE_INIT_TOKEN");

// Stores the permitted-intent set for the active profile. None = Default (all intents).
// Set once during init_with_profile(); read-only afterwards.
static ACTIVE_PROFILE_INTENTS: OnceLock<Option<Vec<MatchedIntent>>> = OnceLock::new();

// Loaded from firewall.toml during init().
static STATIC_CONFIG: OnceLock<config::FirewallConfig> = OnceLock::new();

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
    if token != INIT_TOKEN {
        return Err(crate::FirewallInitError::UnauthorizedInit(
            "Init token mismatch - possible race-to-init attack or misconfiguration. \
             Ensure POLICY_GATE_INIT_TOKEN was set at build time."
                .into(),
        ));
    }

    init_with_profile_internal(profile)
}

/// Development and test initialization path without the build-time token.
///
/// This exists for local test harnesses and compatibility with integration
/// tests. Production callers should prefer `init_with_token()`.
pub fn init() -> Result<(), crate::FirewallInitError> {
    init_with_profile_internal(FirewallProfile::Default)
}

/// Deprecated compatibility path retained for older callers.
pub fn init_with_profile(profile: FirewallProfile) -> Result<(), crate::FirewallInitError> {
    init_with_profile_internal(profile)
}

fn init_with_profile_internal(profile: FirewallProfile) -> Result<(), crate::FirewallInitError> {
    // Validate custom regex before fixing init state so invalid profiles fail cleanly.
    if let Some((id, regex, _intent)) = profile.custom_pattern() {
        regex::Regex::new(regex).map_err(|e| {
            crate::FirewallInitError::PatternCompileFailure(format!(
                "Custom pattern [{id}] regex compile failure: {e}"
            ))
        })?;
    }

    // First successful init fixes the active profile for the process lifetime.
    let _ = ACTIVE_PROFILE_INTENTS.get_or_init(|| profile.permitted_intents());
    let config = STATIC_CONFIG.get_or_init(|| config::FirewallConfig::load().unwrap_or_default());

    let result = INIT_RESULT.get_or_init(|| {
        // Inject dynamic config before the startup self-test warms the matcher set.
        if let Some(custom) = &config.intents {
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

        #[cfg(feature = "semantic")]
        if let (Some(m), Some(t)) = (&config.semantic_model_path, &config.tokenizer_path) {
            crate::semantic::ChannelD::init(m, t)
                .map_err(|e| format!("Channel D init failed: {}", e))?;
        }

        crate::audit::init_audit();
        session::init_session_manager();
        fsm::intent_patterns::startup_self_test().map_err(|errs| errs.join("; "))
    });

    result
        .as_ref()
        .copied()
        .map_err(|e| crate::FirewallInitError::PatternCompileFailure(e.clone()))
}

pub(crate) fn get_config() -> Option<&'static config::FirewallConfig> {
    STATIC_CONFIG.get()
}

pub(crate) fn is_initialised() -> bool {
    matches!(INIT_RESULT.get(), Some(Ok(())))
}

pub(crate) fn active_profile_intents() -> Option<&'static Vec<MatchedIntent>> {
    ACTIVE_PROFILE_INTENTS.get().and_then(|o| o.as_ref())
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
        ),
    }
}
