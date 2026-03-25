// crates/firewall-core/src/profile.rs — Multi-Tenant Firewall Profile System
//
// Safety note: Profile selection happens at init() time only — never during
// evaluate(). The hot-path (evaluate_raw / evaluate) is unaffected.
//
// Available profiles:
//   Default        — Full 12-intent allowlist (same as calling init())
//   CodeAssistant  — Factual Q&A + code tasks + comparisons; translation, creative and
//                    extraction excluded to reduce attack surface
//   CustomerService — Greeting, acknowledgement, summarisation, factual Q&A only;
//                     code generation and extraction excluded
//   Custom(String) — Caller-provided regex for a single custom intent (IP-200).
//                    All other intents follow the Default allowlist.
//                    Used for narrowly scoped deployments that need one extra pattern.

use crate::types::MatchedIntent;

/// A named deployment profile that restricts the effective allowlist.
///
/// Profiles do NOT change the forbidden-pattern tables (FP-003/FP-004/RE-004/RE-005)
/// or any structural checks — only the set of intent classes that can result in Pass.
#[derive(Debug, Clone)]
pub enum FirewallProfile {
    /// Full allowlist: all 12 built-in intent patterns (IP-001 … IP-099).
    /// Equivalent to calling `init()` without a profile.
    Default,

    /// Reduced allowlist for code assistant deployments.
    ///
    /// Permitted intents: QuestionFactual, QuestionCausal, QuestionComparative,
    ///                    TaskCodeGeneration, TaskTextSummarisation, SystemMetaQuery,
    ///                    ConversationalGreeting, ConversationalAcknowledgement
    ///
    /// Blocked intents: TaskTranslation, TaskDataExtraction, StructuredOutput, ControlledCreative
    CodeAssistant,

    /// Reduced allowlist for customer service deployments.
    ///
    /// Permitted intents: ConversationalGreeting, ConversationalAcknowledgement,
    ///                    TaskTextSummarisation, QuestionFactual, QuestionCausal
    ///
    /// Blocked intents: TaskCodeGeneration, TaskTranslation, TaskDataExtraction,
    ///                  QuestionComparative, StructuredOutput, ControlledCreative, SystemMetaQuery
    CustomerService,

    /// Custom profile: extends the Default allowlist with one additional intent pattern.
    ///
    /// `regex` is compiled during `init_with_profile()` — a compile failure returns Err.
    /// The custom intent is assigned intent class `MatchedIntent::QuestionFactual` so it
    /// uses an existing voter-compatible intent. For a genuinely new intent class, extend
    /// `MatchedIntent` in types.rs and open a Change Request (OC-08).
    Custom {
        /// Stable ID for Safety Manual traceability (use IP-2xx range for custom intents).
        id: String,
        /// Regular expression — must compile with the `regex` crate.
        regex: String,
        /// Intent class for voter / audit purposes.
        intent: MatchedIntent,
    },
}

impl FirewallProfile {
    /// Returns the set of `MatchedIntent` values that are permitted to Pass
    /// under this profile. Used to filter Channel A/B decisions in the voter.
    ///
    /// Returns `None` for `Default` (all intents permitted — no filtering needed).
    pub fn permitted_intents(&self) -> Option<Vec<MatchedIntent>> {
        match self {
            FirewallProfile::Default => None,

            FirewallProfile::CodeAssistant => Some(vec![
                MatchedIntent::QuestionFactual,
                MatchedIntent::QuestionCausal,
                MatchedIntent::QuestionComparative,
                MatchedIntent::TaskCodeGeneration,
                MatchedIntent::TaskTextSummarisation,
                MatchedIntent::ConversationalGreeting,
                MatchedIntent::ConversationalAcknowledgement,
                MatchedIntent::SystemMetaQuery,
            ]),

            FirewallProfile::CustomerService => Some(vec![
                MatchedIntent::ConversationalGreeting,
                MatchedIntent::ConversationalAcknowledgement,
                MatchedIntent::TaskTextSummarisation,
                MatchedIntent::QuestionFactual,
                MatchedIntent::QuestionCausal,
            ]),

            FirewallProfile::Custom { intent, .. } => {
                // Custom profiles inherit the Default permitted set (all intents)
                // plus their custom intent. Since Default = all intents, return None.
                let _ = intent;
                None
            }
        }
    }

    /// Returns the custom intent pattern regex and ID if this is a Custom profile.
    pub fn custom_pattern(&self) -> Option<(&str, &str, &MatchedIntent)> {
        match self {
            FirewallProfile::Custom { id, regex, intent } => {
                Some((id.as_str(), regex.as_str(), intent))
            }
            _ => None,
        }
    }

    /// Human-readable name for logging/audit.
    pub fn name(&self) -> &str {
        match self {
            FirewallProfile::Default => "Default",
            FirewallProfile::CodeAssistant => "CodeAssistant",
            FirewallProfile::CustomerService => "CustomerService",
            FirewallProfile::Custom { id, .. } => id.as_str(),
        }
    }
}
