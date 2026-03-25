// fsm/states.rs — exhaustive state enumeration for Channel A FSM
//
// Design rule: adding a state requires updating the Z3 model in
// /verification/channel_a.smt2 and running `cargo test fsm_state_coverage`.

#[derive(Debug)]
pub enum FsmState {
    /// Entry point. No decision has been made.
    Init,
    /// Structural checks passed; input is being tokenised.
    Tokenizing,
    /// Tokenised; running intent classification.
    IntentClassify { tokenised: String },
    /// Classification complete; running allowlist pattern matching.
    PatternMatch { tokenised: String },
    /// No allowlist match found — will emit Block.
    Blocking,
    // NOTE: there is no `Passing` state — a Pass decision is returned
    // directly from PatternMatch as a ChannelDecision, not as a state.
    // This prevents any ambiguous "we're about to pass" intermediate state.
}
