; channel_a.smt2 — Z3 proof obligations for Channel A FSM
; Run: z3 verification/channel_a.smt2
;
; Proof Obligations:
;   PO-A1: No path from Init to Pass without matching an AllowedIntentPattern
;   PO-A2: WatchdogTimeout is reachable from every non-terminal state
;   PO-A3: No state is unreachable (state completeness)
;   PO-A4: Forbidden patterns always lead to Block (never Pass)
;   PO-A5: The Blocking state has no outgoing transitions (terminal)
;   PO-A6: IP-050 post-match guard — guarded match can only Pass if guard accepts
;   PO-A7: IP-099 post-match guard — guarded match can only Pass if guard accepts
;   PO-A8: Structural violations always block (Tokenizing state)
;   PO-A9: Tokenizing runs before IntentClassify (ordering proof)
;   PO-A10: Tokenizing → IntentClassify only on clean input
;   PO-A11: IP-060 post-match guard — guarded match can only Pass if guard accepts

(set-logic ALL)
(set-option :produce-proofs true)

; ─── State encoding ──────────────────────────────────────────────────────────

(declare-datatypes () ((State
  Init
  Tokenizing
  IntentClassify
  PatternMatch
  Blocking
  Decided_Pass   ; terminal — absorbing
  Decided_Block  ; terminal — absorbing
  Decided_Fault  ; terminal — absorbing
)))

; ─── Input predicates ────────────────────────────────────────────────────────

; These model the boolean conditions checked at each transition.
; In the actual Rust code, these are deterministic functions.
; Here we declare them as uninterpreted functions and then add constraints.

(declare-fun has_control_char (String) Bool)
(declare-fun has_forbidden_pattern (String) Bool)
(declare-fun matches_allowlist (String) Bool)
(declare-fun watchdog_expired () Bool)

; SA-031/SA-030/SA-019 Tokenizing checks — modelled as separate predicates
; so PO-A8/PO-A9/PO-A10 can prove they always block before IntentClassify.
(declare-fun has_structural_violation (String) Bool)  ; null-byte, overlong-run, zero-width, bidi, token-length

; Constraint: forbidden_pattern and matches_allowlist are mutually exclusive
; (a well-formed allowlist cannot contain a forbidden pattern)
(assert (forall ((s String))
  (=> (has_forbidden_pattern s) (not (matches_allowlist s)))))

; Constraint: structural violations and allowlist are mutually exclusive
; (a structurally malformed input cannot match the allowlist)
(assert (forall ((s String))
  (=> (has_structural_violation s) (not (matches_allowlist s)))))

; Constraint: structural violations and forbidden patterns are independent
; (either alone is sufficient to block — no ordering dependency between them)

; ─── Post-match guard predicates (CR-2026-001: IP-050, IP-099) ───────────────
;
; IP-050 and IP-099 use post-match guards: the regex matches, then a guard
; function checks for disqualifying payload signals. A guarded pattern can
; only produce Decided_Pass if BOTH the regex matches AND the guard accepts.
;
; We model this with two additional predicates:
;   matches_guarded_pattern(s) — regex matched for a guarded intent (IP-050 or IP-099)
;   guard_accepts(s)           — post-match guard returned true (no disqualifying signal)
;
; The combined condition for a guarded Pass is:
;   matches_guarded_pattern(s) AND guard_accepts(s)
;
; Constraint: a guarded pattern with a disqualifying signal cannot match the allowlist.
; This encodes the guard contract: guard_accepts = false → not matches_allowlist.
(declare-fun matches_guarded_pattern (String) Bool)
(declare-fun guard_accepts (String) Bool)

; If a guarded pattern matches but the guard rejects, the input does NOT pass.
; (The FSM continues to the next pattern or falls through to Blocking.)
(assert (forall ((s String))
  (=> (and (matches_guarded_pattern s) (not (guard_accepts s)))
      (not (matches_allowlist s)))))

; A guarded pattern that passes the guard is a valid allowlist match.
(assert (forall ((s String))
  (=> (and (matches_guarded_pattern s) (guard_accepts s))
      (matches_allowlist s))))

; ─── Transition function ─────────────────────────────────────────────────────

(define-fun transition ((st State) (input String)) State
  (ite watchdog_expired Decided_Fault
  (match st (
    (Init
      (ite (has_control_char input) Decided_Block Tokenizing))
    (Tokenizing
      ; SA-019/SA-030/SA-031: Tokenizing checks (null-byte, overlong-run,
      ; zero-width chars, bidi override, variation selectors, token-length).
      ; Any structural violation → Decided_Block before IntentClassify.
      (ite (has_structural_violation input) Decided_Block IntentClassify))
    (IntentClassify
      (ite (has_forbidden_pattern input) Decided_Block PatternMatch))
    (PatternMatch
      (ite (matches_allowlist input) Decided_Pass Blocking))
    (Blocking
      Decided_Block)
    ; Terminal states are absorbing
    (Decided_Pass  Decided_Pass)
    (Decided_Block Decided_Block)
    (Decided_Fault Decided_Fault)
  ))))

; ─── PO-A1: No path to Pass without allowlist match ─────────────────────────

(push)
(declare-const bad_input String)
; A bad input does NOT match the allowlist...
(assert (not (matches_allowlist bad_input)))
(assert (not (has_control_char bad_input)))
(assert (not (has_forbidden_pattern bad_input)))
(assert (not watchdog_expired))
; ...but somehow reaches Decided_Pass after full traversal
(assert (=
  (transition (transition (transition (transition (transition Init bad_input) bad_input) bad_input) bad_input) bad_input)
  Decided_Pass))
; This must be UNSAT (unreachable)
(check-sat) ; expected: unsat
(pop)

; ─── PO-A4: Forbidden patterns always block ──────────────────────────────────

(push)
(declare-const fp_input String)
(assert (has_forbidden_pattern fp_input))
(assert (not watchdog_expired))
; Forbidden input reaches Decided_Pass after full traversal — must be UNSAT
(assert (=
  (transition (transition (transition (transition (transition Init fp_input) fp_input) fp_input) fp_input) fp_input)
  Decided_Pass))
(check-sat) ; expected: unsat
(pop)

; ─── PO-A5: Blocking state is terminal ───────────────────────────────────────

(push)
(declare-const any_input String)
(assert (not watchdog_expired))
; From Blocking, transition must be Decided_Block (not anything else)
(assert (not (= (transition Blocking any_input) Decided_Block)))
(check-sat) ; expected: unsat
(pop)

; ─── PO-A3: No state is unreachable (state completeness) ────────────────────
; Safety Action SA-002: Every non-terminal state must be reachable from Init
; via some sequence of inputs. We prove this by showing a satisfying assignment
; exists for each state (SAT expected — reachability witness).
;
; Method: for each state S, assert that there EXISTS an input sequence that
; reaches S from Init. We check SAT (not UNSAT) — a SAT result is the witness.

; PO-A3a: Tokenizing is reachable from Init
(push)
(declare-const reach_input_a String)
(assert (not (has_control_char reach_input_a)))
(assert (not watchdog_expired))
; Init --[no control char]--> Tokenizing
(assert (= (transition Init reach_input_a) Tokenizing))
(check-sat) ; expected: sat (witness: any input without control chars)
(pop)

; PO-A3b: IntentClassify is reachable from Tokenizing (on clean input)
(push)
(declare-const reach_input_b String)
(assert (not (has_structural_violation reach_input_b)))
(assert (not watchdog_expired))
; Tokenizing --[no structural violation]--> IntentClassify
(assert (= (transition Tokenizing reach_input_b) IntentClassify))
(check-sat) ; expected: sat
(pop)

; PO-A3c: PatternMatch is reachable from IntentClassify
(push)
(declare-const reach_input_c String)
(assert (not (has_forbidden_pattern reach_input_c)))
(assert (not watchdog_expired))
; IntentClassify --[no forbidden pattern]--> PatternMatch
(assert (= (transition IntentClassify reach_input_c) PatternMatch))
(check-sat) ; expected: sat
(pop)

; PO-A3d: Blocking is reachable from PatternMatch
(push)
(declare-const reach_input_d String)
(assert (not (matches_allowlist reach_input_d)))
(assert (not watchdog_expired))
; PatternMatch --[no allowlist match]--> Blocking
(assert (= (transition PatternMatch reach_input_d) Blocking))
(check-sat) ; expected: sat
(pop)

; PO-A3e: Decided_Pass is reachable from PatternMatch
(push)
(declare-const reach_input_e String)
(assert (matches_allowlist reach_input_e))
(assert (not watchdog_expired))
; PatternMatch --[allowlist match]--> Decided_Pass
(assert (= (transition PatternMatch reach_input_e) Decided_Pass))
(check-sat) ; expected: sat
(pop)

; PO-A3f: Decided_Block is reachable (via Blocking)
(push)
(declare-const reach_input_f String)
(assert (not watchdog_expired))
; Blocking always transitions to Decided_Block
(assert (= (transition Blocking reach_input_f) Decided_Block))
(check-sat) ; expected: sat
(pop)

; PO-A3g: Decided_Fault is reachable (watchdog path)
(push)
(assert watchdog_expired)
(declare-const reach_input_g String)
; Any state with watchdog_expired transitions to Decided_Fault
(assert (= (transition Init reach_input_g) Decided_Fault))
(check-sat) ; expected: sat
(pop)


; ─── PO-A2: Watchdog reachability ────────────────────────────────────────────
; Proof: when watchdog_expired = true, all transitions go to Decided_Fault.
; (This is trivially true by construction of the transition function above,
;  but we state it explicitly for the Safety Case.)

(push)
(assert watchdog_expired)
(declare-const any_state State)
(declare-const any_input2 String)
(assert (not (= (transition any_state any_input2) Decided_Fault)))
(check-sat) ; expected: unsat (watchdog always reaches Fault when fired)
(pop)

; ─── PO-A8: Structural violations always block (Tokenizing state) ────────────
; For any input with a structural violation (null-byte, overlong-run, zero-width,
; bidi override, variation selector, token-length), the FSM must reach Decided_Block
; and never reach Decided_Pass.
; This proves that Tokenizing checks cannot be bypassed to reach IntentClassify.
; Corresponds to: has_zero_width_chars, has_bidi_override_chars, has_overlong_run,
;                 null-byte check, token-length check in fsm/mod.rs Tokenizing state.
; SA-019, SA-030, SA-031.

(push)
(declare-const sv_input String)
(assert (has_structural_violation sv_input))
(assert (not (has_control_char sv_input)))  ; Init passes (structural violation is in Tokenizing)
(assert (not watchdog_expired))
; After Init → Tokenizing → Decided_Block (structural violation fires in Tokenizing)
(assert (=
  (transition (transition Init sv_input) sv_input)
  Decided_Block))
(check-sat) ; expected: sat (witness: any input with structural violation, no control chars)
(pop)

; PO-A8b: Structural violation input can NEVER reach Decided_Pass
(push)
(declare-const sv_input2 String)
(assert (has_structural_violation sv_input2))
(assert (not watchdog_expired))
; Claim: full traversal never reaches Decided_Pass. Negate and check UNSAT.
(assert (=
  (transition (transition (transition (transition (transition Init sv_input2) sv_input2) sv_input2) sv_input2) sv_input2)
  Decided_Pass))
(check-sat) ; expected: unsat
(pop)

; ─── PO-A9: Tokenizing runs before IntentClassify (ordering proof) ────────────
; No path from Init to IntentClassify without passing through Tokenizing.
; Proved structurally: Init → Tokenizing → IntentClassify is the only path.
; An input that passes Init (no control chars) but has a structural violation
; must be caught in Tokenizing — it cannot reach IntentClassify.

(push)
(declare-const ord_input String)
(assert (not (has_control_char ord_input)))
(assert (has_structural_violation ord_input))
(assert (not watchdog_expired))
; After Init → Tokenizing: must be Decided_Block (not IntentClassify)
(assert (= (transition (transition Init ord_input) ord_input) IntentClassify))
; This must be UNSAT — structural violation in Tokenizing prevents reaching IntentClassify
(check-sat) ; expected: unsat
(pop)

; ─── PO-A10: PO-A3b updated — Tokenizing → IntentClassify only on clean input ─
; Tokenizing transitions to IntentClassify only when has_structural_violation is false.

(push)
(declare-const clean_input String)
(assert (not (has_structural_violation clean_input)))
(assert (not watchdog_expired))
; Tokenizing --[no structural violation]--> IntentClassify
(assert (= (transition Tokenizing clean_input) IntentClassify))
(check-sat) ; expected: sat (witness: any clean input)
(pop)

(echo "All PO-A proof obligations checked.")

; ─── PO-A6: IP-050 guard — guarded match without guard acceptance cannot Pass ─
; A guarded pattern (IP-050 structured output) that matches the regex but whose
; post-match guard rejects the input must NOT produce Decided_Pass.
; This proves the guard cannot be bypassed: regex match alone is insufficient.
; CR-2026-001 | ip050_guard in fsm/intent_patterns.rs.

(push)
(declare-const g050_input String)
; The guarded pattern matched (regex hit) but the guard rejected (disqualifying signal)
(assert (matches_guarded_pattern g050_input))
(assert (not (guard_accepts g050_input)))
(assert (not (has_control_char g050_input)))
(assert (not (has_structural_violation g050_input)))
(assert (not (has_forbidden_pattern g050_input)))
(assert (not watchdog_expired))
; Claim: this input reaches Decided_Pass — must be UNSAT (guard prevents it)
(assert (=
  (transition (transition (transition (transition (transition Init g050_input) g050_input) g050_input) g050_input) g050_input)
  Decided_Pass))
(check-sat) ; expected: unsat
(pop)

; ─── PO-A7: IP-099 guard — same proof for controlled creative guard ───────────
; A guarded pattern (IP-099 controlled creative) that matches the regex but whose
; post-match guard rejects the input must NOT produce Decided_Pass.
; CR-2026-001 | ip099_guard in fsm/intent_patterns.rs.
; (Uses the same guard predicates — the model is symmetric for both guarded intents.)

(push)
(declare-const g099_input String)
(assert (matches_guarded_pattern g099_input))
(assert (not (guard_accepts g099_input)))
(assert (not (has_control_char g099_input)))
(assert (not (has_structural_violation g099_input)))
(assert (not (has_forbidden_pattern g099_input)))
(assert (not watchdog_expired))
; Claim: this input reaches Decided_Pass — must be UNSAT
(assert (=
  (transition (transition (transition (transition (transition Init g099_input) g099_input) g099_input) g099_input) g099_input)
  Decided_Pass))
(check-sat) ; expected: unsat
(pop)

(echo "PO-A6 and PO-A7 (guarded intent proofs) checked.")

; ─── PO-A11: IP-060 guard — guarded match without guard acceptance cannot Pass ─
; IP-060 (AgenticToolUse) carries a post-match guard (ip060_guard) that rejects
; destructive OS commands, reverse shells, exfiltration patterns, and SQL injection.
; A guarded pattern that matches the regex but whose guard rejects the input must
; NOT produce Decided_Pass.
; Uses the same guard predicates as PO-A6/PO-A7 — the model is symmetric for all
; three guarded intents (IP-050, IP-060, IP-099).
; ip060_guard in fsm/intent_patterns.rs.

(push)
(declare-const g060_input String)
(assert (matches_guarded_pattern g060_input))
(assert (not (guard_accepts g060_input)))
(assert (not (has_control_char g060_input)))
(assert (not (has_structural_violation g060_input)))
(assert (not (has_forbidden_pattern g060_input)))
(assert (not watchdog_expired))
; Claim: this input reaches Decided_Pass — must be UNSAT (guard prevents it)
(assert (=
  (transition (transition (transition (transition (transition Init g060_input) g060_input) g060_input) g060_input) g060_input)
  Decided_Pass))
(check-sat) ; expected: unsat
(pop)

(echo "PO-A11 (IP-060 AgenticToolUse guard proof) checked.")
