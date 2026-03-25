// crates/firewall-core/src/config.rs — Pluggable Configuration Loading
//
// Safety Action SA-048: Load custom intent patterns and forbidden keywords
// from an optional firewall.toml file at startup.
//
// This module is only active during the init() phase.

use crate::types::{AuditDetailLevel, MatchedIntent};
use serde::Deserialize;
#[cfg(not(target_arch = "wasm32"))]
use std::fs;
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

/// Configuration structure for the firewall.
#[derive(Debug, Deserialize, Default)]
pub struct FirewallConfig {
    /// Optional list of custom intent patterns.
    pub intents: Option<Vec<IntentEntry>>,
    /// Optional list of additional forbidden keywords.
    pub forbidden_keywords: Option<Vec<String>>,
    /// Lookback window for contextual evaluation (Red-Team Strategy 3).
    /// Default is 3 if not specified.
    pub context_window: Option<usize>,
    #[cfg(feature = "semantic")]
    pub semantic_model_path: Option<String>,
    /// Optional path to the tokenizer for Channel D.
    #[cfg(feature = "semantic")]
    pub tokenizer_path: Option<String>,
    /// SA-XXX: Audit detail level for operator review support.
    /// "basic" (default) stores only block_reason and hash.
    /// "detailed" stores full ChannelResult for side-by-side analysis.
    /// Increases audit log size but enables operator_review.py to analyze
    /// DiagnosticDisagreement events with full channel details.
    #[serde(default)]
    pub audit_detail_level: Option<AuditDetailLevel>,
}

/// A single intent pattern entry in the configuration.
#[derive(Debug, Deserialize)]
pub struct IntentEntry {
    /// Stable ID for traceability (e.g., IP-200).
    pub id: String,
    /// Intent class (must match MatchedIntent variants).
    pub intent: MatchedIntent,
    /// Regular expression pattern.
    pub regex: String,
}

impl FirewallConfig {
    /// Loads the configuration from the default location (firewall.toml).
    /// Returns Default if the file does not exist.
    /// Returns Err if the file exists but is malformed.
    pub fn load() -> Result<Self, String> {
        #[cfg(target_arch = "wasm32")]
        {
            // WASM/Edge environments usually don't have a filesystem.
            // Return default/empty config.
            Ok(FirewallConfig::default())
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let path = Path::new("firewall.toml");
            if !path.exists() {
                return Ok(FirewallConfig::default());
            }

            let content = fs::read_to_string(path)
                .map_err(|e| format!("Failed to read firewall.toml: {e}"))?;

            toml::from_str(&content).map_err(|e| format!("Failed to parse firewall.toml: {e}"))
        }
    }
}
