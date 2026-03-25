// voter.rs — 1oo2D Voter (one-out-of-two with diagnostics)
//
// Safety architecture (inspired by redundant voting patterns, e.g. IEC 61508 §6.7.3):
//   HFT = 1: the system tolerates one channel failure without entering
//   an unsafe state. A failed channel always causes BLOCK (not PASS).
//
// Voting logic:
//   ┌──────────┬──────────┬──────────────────────────┐
//   │ Channel A │ Channel B │ Voter Output             │
//   ├──────────┼──────────┼──────────────────────────┤
//   │ Pass(X)  │ Pass(X)  │ Pass (agreement)          │
//   │ Pass(X)  │ Pass(Y)  │ DiagnosticAgreement*      │ ← intent disagreement logged
//   │ Pass     │ Block    │ DiagnosticDisagreement→Block│
//   │ Block    │ Pass     │ DiagnosticDisagreement→Block│
//   │ Block    │ Block    │ Block                      │
//   │ Fault    │ *        │ Block (channel failure)    │
//   │ *        │ Fault    │ Block (channel failure)    │
//   └──────────┴──────────┴──────────────────────────┘
//   *DiagnosticAgreement: both channels agree on Pass/Block but disagree
//    on the matched intent — permitted but flagged for review.
//
// Diagnostic Coverage target: ≥ 90% (DC_medium, analogous to IEC 61508 Table A.14).
// The voter detects: channel Fault, Pass/Block disagreement, intent mismatch.
// Undetected failure mode: both channels identically miscategorise an input
// (common-cause failure — mitigated by diversity of A vs B).

use crate::types::{ChannelDecision, ChannelResult, VerdictKind};

pub struct Voter;

impl Voter {
    pub fn decide(a: &ChannelResult, b: &ChannelResult) -> VerdictKind {
        match (&a.decision, &b.decision) {
            // Both faulted
            (ChannelDecision::Fault { .. }, ChannelDecision::Fault { .. }) => VerdictKind::Block,

            // Any fault → Block (fail-closed, HFT=1)
            (ChannelDecision::Fault { .. }, _) | (_, ChannelDecision::Fault { .. }) => {
                VerdictKind::Block
            }

            // Both Block → Block (no disagreement)
            (ChannelDecision::Block { .. }, ChannelDecision::Block { .. }) => VerdictKind::Block,

            // Both Pass → check intent agreement
            (ChannelDecision::Pass { intent: ia }, ChannelDecision::Pass { intent: ib }) => {
                if ia == ib {
                    VerdictKind::Pass
                } else {
                    // Intent disagreement — both channels agree the input is safe (Pass),
                    // but disagree on which intent matched. is_pass() returns true for
                    // DiagnosticAgreement — the input is allowed through. The disagreement
                    // is logged for operator review (SR-008: review within 72 h).
                    VerdictKind::DiagnosticAgreement
                }
            }

            // One Pass, one Block → critical disagreement → Block + diagnostic
            (ChannelDecision::Pass { .. }, ChannelDecision::Block { .. })
            | (ChannelDecision::Block { .. }, ChannelDecision::Pass { .. }) => {
                VerdictKind::DiagnosticDisagreement
            }
        }
    }
}
