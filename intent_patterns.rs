// fsm/intent_patterns.rs — Allowlist of permitted intent patterns
//
// CRITICAL SAFETY NOTE:
//   This file IS the safety-critical allowlist. Every pattern here defines
//   an input class that is explicitly permitted to proceed to the LLM.
//   Changes require: CR (Change Request) → peer review → Z3 re-proof → release.
//
// Pattern authoring rules:
//   1. Patterns are applied in declaration order — first match wins.
//   2. Patterns must be mutually exclusive where possible (audited by Z3).
//   3. Each pattern has a stable ID (IP-xxx) for Safety Manual cross-reference.
//   4. Regex must compile at crate load time — tested by startup_self_test().

use crate::types::MatchedIntent;
use regex::Regex;
use std::sync::OnceLock;

pub struct IntentPattern {
    pub id: &'static str,
    pub intent: MatchedIntent,
    regex_src: &'static str,
    compiled: OnceLock<Regex>,
}

impl IntentPattern {
    const fn new(id: &'static str, intent: MatchedIntent, regex_src: &'static str) -> Self {
        Self {
            id,
            intent,
            regex_src,
            compiled: OnceLock::new(),
        }
    }

    pub fn matches(&self, input: &str) -> bool {
        let re = self.compiled.get_or_init(|| {
            Regex::new(self.regex_src)
                .unwrap_or_else(|e| panic!("Safety-critical regex compile failure [{id}]: {e}", id = self.id))
        });
        re.is_match(input)
    }

    /// Called during startup_self_test — verifies compilation before any live traffic.
    pub fn verify_compile(&self) -> Result<(), String> {
        Regex::new(self.regex_src)
            .map(|_| ())
            .map_err(|e| format!("[{}] regex compile error: {}", self.id, e))
    }
}

// ─── The Allowlist ─────────────────────────────────────────────────────────────
//
// Regex notes:
//   • (?i) = case-insensitive
//   • All patterns are anchored with word boundaries where intent demands it
//   • No backreferences, no lookahead beyond \b — keeps evaluation O(n)
//
// To add an intent:
//   1. Extend MatchedIntent enum in types.rs
//   2. Add pattern here with next sequential IP-xxx ID
//   3. Add FSM transition in fsm/mod.rs PatternMatch arm (no change needed if
//      pattern is purely regex-based — the loop handles it automatically)
//   4. Add Z3 assertion in /verification/channel_a.smt2
//   5. Open Change Request, get peer sign-off

pub static INTENT_PATTERNS: &[IntentPattern] = &[
    // ── Factual questions ────────────────────────────────────────────────────
    IntentPattern::new(
        "IP-001",
        MatchedIntent::QuestionFactual,
        r"(?i)\b(what|who|where|when|which|how many|how much)\b.{0,200}\?$",
    ),
    IntentPattern::new(
        "IP-002",
        MatchedIntent::QuestionCausal,
        r"(?i)\b(why|how does|how do|what causes|what makes|explain why)\b.{0,200}\?$",
    ),
    IntentPattern::new(
        "IP-003",
        MatchedIntent::QuestionComparative,
        r"(?i)\b(compare|difference between|versus|vs\.?|better than|worse than)\b.{0,300}",
    ),

    // ── Tasks ────────────────────────────────────────────────────────────────
    IntentPattern::new(
        "IP-010",
        MatchedIntent::TaskCodeGeneration,
        r"(?i)\b(write|generate|create|implement|build|code|program)\b.{0,50}\b(function|class|module|script|snippet|code|program|algorithm)\b",
    ),
    IntentPattern::new(
        "IP-011",
        MatchedIntent::TaskTextSummarisation,
        r"(?i)\b(summarize|summarise|summary of|tl;?dr|give me the key points|condense)\b",
    ),
    IntentPattern::new(
        "IP-012",
        MatchedIntent::TaskTranslation,
        r"(?i)\b(translate|übersetz|traduire|traduce|перевод)\b.{0,100}\b(to|into|auf|en|в)\b",
    ),
    IntentPattern::new(
        "IP-013",
        MatchedIntent::TaskDataExtraction,
        r"(?i)\b(extract|pull out|list all|find all|get all)\b.{0,80}\b(from|in)\b",
    ),

    // ── Conversational ───────────────────────────────────────────────────────
    IntentPattern::new(
        "IP-020",
        MatchedIntent::ConversationalGreeting,
        r"(?i)^(hi|hello|hey|good (morning|afternoon|evening)|moin|hallo|servus|grüß gott|salut|ciao|howdy)[!.,\s]*$",
    ),
    IntentPattern::new(
        "IP-021",
        MatchedIntent::ConversationalAcknowledgement,
        r"(?i)^(ok|okay|thanks|thank you|danke|merci|got it|understood|sure|alright|sounds good|perfect)[!.,\s]*$",
    ),

    // ── System meta ─────────────────────────────────────────────────────────
    IntentPattern::new(
        "IP-030",
        MatchedIntent::SystemMetaQuery,
        r"(?i)\b(what (model|version|are you)|who (made|built|created) you|what can you do|what are your capabilities)\b",
    ),
];

// ─── Startup self-test ────────────────────────────────────────────────────────

/// Must be called at process startup before any evaluate() call.
/// Returns Err with all compile failures if any pattern is broken.
/// Failing this test must prevent the firewall from starting (fail-closed).
pub fn startup_self_test() -> Result<(), Vec<String>> {
    let errors: Vec<String> = INTENT_PATTERNS
        .iter()
        .filter_map(|p| p.verify_compile().err())
        .collect();

    if errors.is_empty() { Ok(()) } else { Err(errors) }
}
