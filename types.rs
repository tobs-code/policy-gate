// types.rs — canonical type definitions for the prompt firewall
// All types are designed for exhaustive pattern matching (no catch-all arms in safety code).

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ─── Input ────────────────────────────────────────────────────────────────────

/// Raw prompt input entering the safety boundary.
/// Normalisation (trim, unicode NFC, max-length truncation) happens before
/// this struct is constructed — normalised text is immutable hereafter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptInput {
    /// Normalised prompt text (max 8 192 chars after truncation).
    pub text: String,
    /// Optional caller-supplied context tag (e.g. "user", "tool", "system").
    pub role: Option<String>,
    /// Monotonic timestamp (ns since UNIX epoch) assigned at entry boundary.
    pub ingested_at_ns: u128,
}

impl PromptInput {
    pub fn new(raw: impl Into<String>) -> Self {
        let raw = raw.into();
        let text = Self::normalise(&raw);
        let ingested_at_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos();
        Self { text, role: None, ingested_at_ns }
    }

    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }

    fn normalise(raw: &str) -> String {
        // Safety requirement: normalisation must be deterministic and lossless
        // for safety-relevant characters. We trim whitespace and enforce max length.
        // Unicode NFC normalisation is deliberately left to the caller for now
        // (requires external crate; tracked in Safety Action #SA-003).
        let trimmed = raw.trim();
        if trimmed.len() > 8_192 {
            trimmed[..8_192].to_string()
        } else {
            trimmed.to_string()
        }
    }
}

// ─── Channel Results ──────────────────────────────────────────────────────────

/// Decision produced by a single channel (A or B).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelDecision {
    /// Input matches an explicitly allowed intent pattern.
    Pass { intent: MatchedIntent },
    /// Input did not match any allowed pattern — fail-closed default.
    Block { reason: BlockReason },
    /// Channel encountered an internal fault (watchdog, panic-catch, etc.).
    /// A Fault in *any* channel is treated as Block by the voter.
    Fault { code: FaultCode },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelResult {
    pub channel: ChannelId,
    pub decision: ChannelDecision,
    /// Wall-clock elapsed time for this channel's evaluation (microseconds).
    pub elapsed_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelId { A, B }

// ─── Intent / Block / Fault taxonomy ─────────────────────────────────────────

/// Exhaustive enumeration of intents the firewall explicitly recognises.
/// Adding a new intent requires: (1) pattern definition, (2) FSM transition,
/// (3) Z3 proof update, (4) Safety Manual addendum — tracked as a change request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchedIntent {
    QuestionFactual,
    QuestionCausal,
    QuestionComparative,
    TaskCodeGeneration,
    TaskTextSummarisation,
    TaskTranslation,
    TaskDataExtraction,
    ConversationalGreeting,
    ConversationalAcknowledgement,
    /// Explicitly permitted meta-queries about the model/system.
    SystemMetaQuery,
}

/// Structured reason for a Block decision — machine-readable for the audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockReason {
    NoIntentMatch,
    ForbiddenPattern { pattern_id: &'static str },
    ExceededMaxLength,
    WatchdogTimeout,
    /// Input contained a structural anomaly (e.g. null-byte, control chars).
    MalformedInput { detail: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultCode {
    WatchdogFired,
    InternalPanic,
    RegexCompilationFailure, // should never happen at runtime; caught at startup
}

// ─── Voter Output ─────────────────────────────────────────────────────────────

/// Final verdict emitted by the 1oo2D voter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictKind {
    /// Both channels agreed: Pass.
    Pass,
    /// At least one channel returned Block or Fault.
    Block,
    /// Both channels agree on block/pass but via different reasoning paths —
    /// logged as a diagnostic event even if the outcome is Block.
    /// Example: A=Pass(QuestionFactual), B=Pass(QuestionCausal) → disagreement
    /// on *intent* even though both pass → Diagnostic + Pass.
    DiagnosticAgreement,
    /// Channels disagree on Pass/Block. Always results in Block.
    DiagnosticDisagreement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub kind: VerdictKind,
    pub channel_a: ChannelResult,
    pub channel_b: ChannelResult,
    pub audit: AuditEntry,
}

impl Verdict {
    /// True iff the prompt is permitted to proceed to the LLM.
    pub fn is_pass(&self) -> bool {
        matches!(self.kind, VerdictKind::Pass | VerdictKind::DiagnosticAgreement)
    }
}

// ─── Audit ────────────────────────────────────────────────────────────────────

/// Immutable audit record attached to every Verdict.
/// The audit trail MUST be persisted by the caller — the firewall only produces it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonic counter managed by the caller; 0 if not set.
    pub sequence: u64,
    pub ingested_at_ns: u128,
    pub decided_at_ns: u128,
    pub total_elapsed_us: u64,
    pub verdict_kind: VerdictKind,
    /// SHA-256 hex of the normalised input. Never store the raw text in prod audit logs.
    pub input_hash: String,
    /// Schema version for forward compatibility. Current: 2.
    /// v1: basic audit (input_hash only)
    /// v2: full channel results + input text for operator review
    pub schema_version: u32,
    /// Full Channel A result for side-by-side operator review.
    /// Only populated when audit.store_channel_results = true in config.
    pub channel_a_result: Option<ChannelResult>,
    /// Full Channel B result for side-by-side operator review.
    /// Only populated when audit.store_channel_results = true in config.
    pub channel_b_result: Option<ChannelResult>,
    /// Original input text for operator review.
    /// Only populated when audit.store_input_text = true in config.
    /// WARNING: May contain sensitive data — use only in non-production environments.
    pub input_text: Option<String>,
}
