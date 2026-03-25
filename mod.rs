// fsm/mod.rs — Channel A: Allowlist-based Finite State Machine
//
// Safety rationale (IEC 61508 §7.4.4):
//   • All states are explicitly enumerated — no implicit "else" paths.
//   • Every transition has a single, named condition.
//   • The FSM is fail-closed: any undefined input → State::Blocking.
//   • Watchdog deadline (WATCHDOG_DEADLINE_US) is checked at every state entry.
//
// Z3 proof obligations (see /verification/channel_a.smt2):
//   [PO-A1] ∀ input: ¬∃ path from Init to Decided(Pass) without matching
//           an AllowedIntentPattern.
//   [PO-A2] WatchdogTimeout is reachable from every state.
//   [PO-A3] No state is unreachable (completeness).

pub mod states;
pub mod intent_patterns;

use crate::types::{
    BlockReason, ChannelDecision, ChannelId, ChannelResult, FaultCode, MatchedIntent,
};
use intent_patterns::{IntentPattern, INTENT_PATTERNS};
use states::FsmState;
use std::time::Instant;

/// Watchdog: if Channel A takes longer than this, it self-terminates → Fault.
/// 50 ms is conservative for a regex-based FSM; worst-case analysis in Safety Manual §5.2.
pub const WATCHDOG_DEADLINE_US: u64 = 50_000; // 50 ms

pub struct ChannelA;

impl ChannelA {
    pub fn evaluate(input: &str) -> ChannelResult {
        let start = Instant::now();
        let decision = run_fsm(input, start);
        let elapsed_us = start.elapsed().as_micros() as u64;
        ChannelResult {
            channel: ChannelId::A,
            decision,
            elapsed_us,
        }
    }
}

fn run_fsm(input: &str, start: Instant) -> ChannelDecision {
    let mut state = FsmState::Init;

    loop {
        // Watchdog check at every state entry (online monitoring)
        if start.elapsed().as_micros() as u64 >= WATCHDOG_DEADLINE_US {
            return ChannelDecision::Fault {
                code: FaultCode::WatchdogFired,
            };
        }

        state = match state {
            FsmState::Init => {
                // Structural pre-checks before expensive pattern matching.
                if contains_control_chars(input) {
                    return ChannelDecision::Block {
                        reason: BlockReason::MalformedInput {
                            detail: "control characters detected".into(),
                        },
                    };
                }
                FsmState::Tokenizing
            }

            FsmState::Tokenizing => {
                // Lightweight tokenisation: split into sentences / clauses.
                // Full NLP tokeniser is out-of-scope for the safety function;
                // we operate on normalised unicode code points only.
                // (Safety Action #SA-007: evaluate adding SIMD-accelerated
                //  unicode segmenter without breaking determinism guarantees.)
                FsmState::IntentClassify { tokenised: input.to_string() }
            }

            FsmState::IntentClassify { ref tokenised } => {
                // Check each forbidden-pattern first (early block, cheaper).
                for fp in FORBIDDEN_PATTERNS {
                    if fp.is_match(tokenised) {
                        return ChannelDecision::Block {
                            reason: BlockReason::ForbiddenPattern {
                                pattern_id: fp.id,
                            },
                        };
                    }
                }
                FsmState::PatternMatch { tokenised: tokenised.clone() }
            }

            FsmState::PatternMatch { ref tokenised } => {
                // Allowlist check: iterate all IntentPatterns, return first match.
                // Ordering is deterministic (static array, no runtime reordering).
                for pattern in INTENT_PATTERNS.iter() {
                    if pattern.matches(tokenised) {
                        return ChannelDecision::Pass {
                            intent: pattern.intent.clone(),
                        };
                    }
                }
                // Exhausted all patterns — fail-closed.
                FsmState::Blocking
            }

            FsmState::Blocking => {
                return ChannelDecision::Block {
                    reason: BlockReason::NoIntentMatch,
                };
            }
        };
    }
}

// ─── Forbidden patterns (deny-before-allow, structural anomalies) ─────────────

struct ForbiddenPattern {
    id: &'static str,
    /// Compiled at startup; compile errors caught by the startup self-test.
    matcher: fn(&str) -> bool,
}

impl ForbiddenPattern {
    fn is_match(&self, s: &str) -> bool {
        (self.matcher)(s)
    }
}

// These patterns are NOT the safety gate — they are fast pre-filters for
// structurally invalid inputs. The real gate is the allowlist in PatternMatch.
static FORBIDDEN_PATTERNS: &[ForbiddenPattern] = &[
    ForbiddenPattern {
        id: "FP-001-NULL-BYTE",
        matcher: |s| s.contains('\0'),
    },
    ForbiddenPattern {
        id: "FP-002-OVERLONG-REPEATED",
        // Heuristic: 200+ consecutive identical chars (likely padding attack)
        matcher: |s| {
            let mut count = 1u32;
            let mut prev = '\0';
            for c in s.chars() {
                if c == prev {
                    count += 1;
                    if count > 200 { return true; }
                } else {
                    count = 1;
                    prev = c;
                }
            }
            false
        },
    },
];

fn contains_control_chars(s: &str) -> bool {
    s.chars().any(|c| {
        let cp = c as u32;
        // Allow: tab (9), newline (10), carriage return (13)
        // Block: all other C0/C1 control characters
        matches!(cp, 0..=8 | 11..=12 | 14..=31 | 127 | 128..=159)
    })
}
