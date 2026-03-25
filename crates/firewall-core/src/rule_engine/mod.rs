// rule_engine/mod.rs — Channel B: deterministic rule engine
//
// No regex, no ML. Pure structural/lexical analysis.
// Diversity from Channel A (FSM + regex) prevents common-cause failures.
//
// SA-032: Channel B Watchdog.
// Channel A has a 50 ms watchdog (WallClock/MockClock). Channel B has no
// equivalent — a pathological input that exhausts all rules without matching
// would run unbounded. In practice the rule table is O(n·k) where n = input
// length and k = number of rules (~15), bounded by the 8192-byte input limit.
// Worst-case: ~15 × 8192 char scans ≈ 120k operations — well under 1 ms.
// We add a soft watchdog (50 ms, same deadline as Channel A) that returns
// a Fault if the rule engine exceeds the deadline. This closes the asymmetry
// documented in FMEA FM-05 and makes Channel B's timeout behaviour symmetric
// with Channel A for the voter's fail-closed invariant.

pub mod egress;
pub mod rules;

use crate::types::{
    BlockReason, ChannelDecision, ChannelId, ChannelResult, FaultCode, MatchedIntent,
};
use rules::RULE_TABLE;
use std::time::Instant;

/// Watchdog deadline for Channel B — mirrors Channel A WATCHDOG_DEADLINE_US.
/// Debug builds get 500 ms — same rationale as Channel A: regex OnceLock
/// initialisation on first call can take ~280 ms in unoptimised builds.
#[cfg(not(debug_assertions))]
pub const CHANNEL_B_WATCHDOG_US: u64 = 50_000; // 50 ms  (release)
#[cfg(debug_assertions)]
pub const CHANNEL_B_WATCHDOG_US: u64 = 500_000; // 500 ms (debug)

/// Intermediate outcome from a single rule evaluation.
pub enum RuleOutcome {
    Pass(MatchedIntent),
    Block(BlockReason),
    /// Rule does not apply to this input — continue to next rule.
    Continue,
}

pub struct ChannelB;

impl ChannelB {
    /// Evaluate a normalised input string through the rule engine.
    ///
    /// IMPORTANT: `input` MUST be the normalised text from `PromptInput::text`,
    /// not a raw string. Calling this directly with an unnormalised string bypasses
    /// NFKC, combining-mark stripping, confusable normalisation, and separator-strip
    /// (SA-003, SA-029, SA-038, SA-045). Use `evaluate_raw()` or `evaluate()` from
    /// `lib.rs` for the full pipeline.
    pub fn evaluate(input: &crate::types::PromptInput) -> ChannelResult {
        let start = Instant::now();
        let decision = run_rules(input, &start);
        // as_micros() returns u128; saturating cast to u64 (overflow at ~584k years).
        let elapsed_us = start.elapsed().as_micros().min(u64::MAX as u128) as u64;
        ChannelResult {
            channel: ChannelId::B,
            decision,
            elapsed_us,
            similarity: None,
        }
    }
}

fn run_rules(input: &crate::types::PromptInput, start: &Instant) -> ChannelDecision {
    let text = &input.text;

    // SA-048: Obfuscation check (Diversity).
    // If the normalisation pipeline flagged suspicious hidden characters,
    // we block here in Channel B as well.
    if input.has_obfuscation {
        return ChannelDecision::Block {
            reason: BlockReason::MalformedInput {
                detail: "obfuscation characters detected".into(),
            },
        };
    }

    for rule in RULE_TABLE {
        // SA-032: watchdog check before each rule evaluation.
        if start.elapsed().as_micros() as u64 >= CHANNEL_B_WATCHDOG_US {
            return ChannelDecision::Fault {
                code: FaultCode::WatchdogFired,
            };
        }
        match (rule.evaluate)(text) {
            RuleOutcome::Pass(intent) => return ChannelDecision::Pass { intent },
            RuleOutcome::Block(reason) => return ChannelDecision::Block { reason },
            RuleOutcome::Continue => continue,
        }
    }

    // SA-048: Check for custom intent patterns (pluggable configuration) in Channel B.
    // To maintain diversity, Channel B is primarily static. For custom patterns
    // provided via TOML, we allow Channel B to use the same regex matching as
    // Channel A. This is a documented trade-off for extensibility.
    for pattern in crate::fsm::intent_patterns::intent_patterns() {
        // SA-032: watchdog check also during custom pattern fallback matching.
        if start.elapsed().as_micros() as u64 >= CHANNEL_B_WATCHDOG_US {
            return ChannelDecision::Fault {
                code: FaultCode::WatchdogFired,
            };
        }
        // Only run custom patterns in Channel B's fallback. Static patterns
        // (IP-0xx) MUST remain diversified via RULE_TABLE.
        if !pattern.id.starts_with("IP-0") && pattern.matches(text) {
            return ChannelDecision::Pass {
                intent: pattern.intent.clone(),
            };
        }
    }

    // No rule matched — fail-closed
    ChannelDecision::Block {
        reason: BlockReason::NoIntentMatch,
    }
}
