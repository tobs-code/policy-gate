// fsm/states.rs — exhaustive state enumeration for Channel A FSM
//
// Design rule: adding a state requires updating the Z3 model in
// /verification/channel_a.smt2 and running `cargo test fsm_state_coverage`.
//
// Note on token cloning: IntentClassify and PatternMatch carry a Vec<String>
// of tokens. The transition IntentClassify → PatternMatch clones this Vec.
// FsmState itself does not derive Clone — the clone is explicit on the field
// only, keeping the state machine transitions intentional. (G-33)

#[derive(Debug)]
pub enum FsmState {
    /// Entry point. No decision has been made.
    Init,
    /// Structural pre-processing layer.
    ///
    /// Responsibilities (centralised here, not scattered across FP-00x):
    ///   1. Reject inputs containing C0/C1 control characters (Init raw-scan).
    ///   2. Reject null bytes (belt-and-suspenders after Init).
    ///   3. Reject inputs with > MAX_CONSECUTIVE_IDENTICAL_CHARS (200) identical
    ///      consecutive chars — overlong-repeat guard (was FP-002).
    ///   4. Reject zero-width / invisible formatting characters
    ///      (FP-005, SA-019: U+200B, U+200C, U+200D, U+FEFF, U+2060, U+00AD).
    ///   5. Reject Unicode Bidirectional override / isolate characters
    ///      (FP-007, SA-030: U+202A–U+202E, U+2066–U+2069, U+200E/F).
    ///   6. Split input into tokens on whitespace boundaries.
    ///   7. Reject any token exceeding MAX_TOKEN_CHARS (512) — obfuscation guard.
    ///
    /// Note: Variation Selectors (U+FE00–U+FE0F, U+E0100–U+E01EF, SA-031) are
    /// stripped upstream in PromptInput::normalise() before the FSM runs —
    /// they never reach this state.
    ///
    /// On success, produces a Vec<String> of clean tokens passed downstream.
    /// On failure, returns a Block decision directly — never advances to IntentClassify.
    Tokenizing,
    /// Tokenised; running forbidden-pattern checks then intent classification.
    IntentClassify { tokens: Vec<String> },
    /// Classification complete; running allowlist pattern matching.
    PatternMatch { tokens: Vec<String> },
    /// No allowlist match found — will emit Block.
    Blocking,
    // NOTE: there is no `Passing` state — a Pass decision is returned
    // directly from PatternMatch as a ChannelDecision, not as a state.
    // This prevents any ambiguous "we're about to pass" intermediate state.
}
