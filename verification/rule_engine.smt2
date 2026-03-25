; rule_engine.smt2 — Z3 proof obligations for Channel B Rule Engine
; Run: z3 verification/rule_engine.smt2
;
; Proof Obligations:
;   PO-RE1: RE-001 (giant token) always blocks — no giant-token input can Pass
;   PO-RE2: RE-002 (injection markers) always blocks — no injection input can Pass
;   PO-RE3: RE-003 (hijack phrases) always blocks — no hijack input can Pass
;   PO-RE4: Block rules are evaluated before allow rules (priority ordering)
;   PO-RE5: Fail-closed — if no rule matches, result is Block (never Pass)
;   PO-RE6: RE-002 and RE-003 are mutually reinforcing — either alone is sufficient to block
;
; Modelling approach:
;   Channel B is a sequential rule table. We model it as a function over
;   abstract boolean predicates (has_giant_token, has_injection_marker, etc.)
;   and prove the safety properties hold for ALL possible input combinations.
;
; Corresponds to: crates/firewall-core/src/rule_engine/rules.rs
;                 SAFETY_MANUAL.md §5

; ─── Rule outcome type ────────────────────────────────────────────────────────

(declare-datatypes () ((RuleOutcome
  (RPass (matched_intent Int))  ; allow — intent 0..9
  RBlock                        ; block
  RContinue                     ; no opinion — next rule
)))

; ─── Input predicates ────────────────────────────────────────────────────────
; Abstract boolean properties of the input string.
; In Rust these are pure structural/lexical checks (no regex).

(declare-fun has_giant_token (String) Bool)       ; RE-001: token > 512 chars
(declare-fun has_injection_marker (String) Bool)  ; RE-002: injection keywords
(declare-fun has_hijack_phrase (String) Bool)     ; RE-003: persona hijack
(declare-fun matches_allow_rule (String) Bool)    ; RE-010..RE-040: any allow rule

; Constraint: block predicates and allow predicates are mutually exclusive.
; A well-formed allowlist cannot contain injection or hijack patterns.
(assert (forall ((s String))
  (=> (has_injection_marker s) (not (matches_allow_rule s)))))
(assert (forall ((s String))
  (=> (has_hijack_phrase s) (not (matches_allow_rule s)))))
(assert (forall ((s String))
  (=> (has_giant_token s) (not (matches_allow_rule s)))))


; ─── Rule engine function ─────────────────────────────────────────────────────
; Models the sequential rule evaluation in rules.rs.
; Block rules (RE-001, RE-002, RE-003) are checked first.
; Allow rules (RE-010..RE-040) are checked only if no block rule fired.
; If no rule matches → RBlock (fail-closed).

(define-fun rule_engine ((s String)) RuleOutcome
  (ite (has_giant_token s)      RBlock
  (ite (has_injection_marker s) RBlock
  (ite (has_hijack_phrase s)    RBlock
  (ite (matches_allow_rule s)   (RPass 0)   ; intent id simplified to 0 for proof
  RBlock)))))                               ; fail-closed: no match → Block

; Helper: is the outcome a Pass?
(define-fun re-is-pass ((r RuleOutcome)) Bool
  (is-RPass r))

; ─── PO-RE1: Giant token always blocks ───────────────────────────────────────
; For any input with a giant token, rule_engine must return RBlock.

(push)
(declare-const s1 String)
(assert (has_giant_token s1))
; Claim: result is RBlock. Negate and check UNSAT.
(assert (re-is-pass (rule_engine s1)))
(check-sat) ; expected: unsat
(pop)

; ─── PO-RE2: Injection marker always blocks ──────────────────────────────────
; For any input containing an injection marker, rule_engine must return RBlock.

(push)
(declare-const s2 String)
(assert (has_injection_marker s2))
; Claim: result is RBlock. Negate and check UNSAT.
(assert (re-is-pass (rule_engine s2)))
(check-sat) ; expected: unsat
(pop)

; ─── PO-RE3: Hijack phrase always blocks ─────────────────────────────────────
; For any input containing a hijack phrase, rule_engine must return RBlock.

(push)
(declare-const s3 String)
(assert (has_hijack_phrase s3))
; Claim: result is RBlock. Negate and check UNSAT.
(assert (re-is-pass (rule_engine s3)))
(check-sat) ; expected: unsat
(pop)

; ─── PO-RE4: Block rules have priority over allow rules ──────────────────────
; An input that triggers a block rule AND matches an allow rule must still block.
; (In practice the mutual-exclusion constraint above prevents this, but we
;  prove it explicitly for the safety case.)

(push)
(declare-const s4 String)
; Hypothetically: injection marker present AND allow rule matches
(assert (has_injection_marker s4))
(assert (matches_allow_rule s4))
; Claim: result is still RBlock. Negate and check UNSAT.
(assert (re-is-pass (rule_engine s4)))
(check-sat) ; expected: unsat (block rule fires first)
(pop)

; ─── PO-RE5: Fail-closed — no match → Block ──────────────────────────────────
; An input that triggers no block rule AND no allow rule must result in RBlock.

(push)
(declare-const s5 String)
(assert (not (has_giant_token s5)))
(assert (not (has_injection_marker s5)))
(assert (not (has_hijack_phrase s5)))
(assert (not (matches_allow_rule s5)))
; Claim: result is RBlock. Negate and check UNSAT.
(assert (re-is-pass (rule_engine s5)))
(check-sat) ; expected: unsat
(pop)

; ─── PO-RE6: RE-002 alone is sufficient to block (no allow rule can override) ─

(push)
(declare-const s6 String)
(assert (has_injection_marker s6))
; Even if hypothetically all other predicates are false, injection alone blocks.
(assert (not (has_giant_token s6)))
(assert (not (has_hijack_phrase s6)))
; Claim: result is RBlock. Negate and check UNSAT.
(assert (re-is-pass (rule_engine s6)))
(check-sat) ; expected: unsat
(pop)

; ─── PO-RE7: RE-003 alone is sufficient to block ─────────────────────────────

(push)
(declare-const s7 String)
(assert (has_hijack_phrase s7))
(assert (not (has_giant_token s7)))
(assert (not (has_injection_marker s7)))
; Claim: result is RBlock. Negate and check UNSAT.
(assert (re-is-pass (rule_engine s7)))
(check-sat) ; expected: unsat
(pop)

; ─── PO-RE8: Global fail-closed invariant ────────────────────────────────────
; For ALL inputs: if any block predicate is true, result is never Pass.

(push)
(declare-const s8 String)
(assert (or (has_giant_token s8) (has_injection_marker s8) (has_hijack_phrase s8)))
; Claim: result is never Pass. Negate and check UNSAT.
(assert (re-is-pass (rule_engine s8)))
(check-sat) ; expected: unsat
(pop)

(echo "All PO-RE proof obligations checked.")
