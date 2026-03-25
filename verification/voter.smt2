; voter.smt2 — Z3 proof obligations for the 1oo2D Voter
; Run: z3 verification/voter.smt2
;
; Proof Obligations:
;   PO-V1: Both channels Pass (same intent) → Voter outputs Pass
;   PO-V2: Both channels Pass (different intent) → Voter outputs DiagnosticAgreement (still Pass-class)
;   PO-V3: Channel A Pass, Channel B Block → Voter outputs DiagnosticDisagreement (Block-class)
;   PO-V4: Channel A Block, Channel B Pass → Voter outputs DiagnosticDisagreement (Block-class)
;   PO-V5: Both channels Block → Voter outputs Block
;   PO-V6: Channel A Fault → Voter outputs Block (fail-closed, HFT=1)
;   PO-V7: Channel B Fault → Voter outputs Block (fail-closed, HFT=1)
;
; Safety property encoded: the voter NEVER outputs Pass when either channel
; is in a Fault or Block state (fail-closed invariant).
;
; Corresponds to: crates/firewall-core/src/voter.rs
;                 SAFETY_MANUAL.md §6.1 truth table
;
; Intent ID range: 0..12 (13 intents — matches PATTERN_REFS in intent_patterns.rs)
;   0  QuestionFactual              (IP-001)
;   1  QuestionCausal               (IP-002)
;   2  QuestionComparative          (IP-003)
;   3  TaskCodeGeneration           (IP-010)
;   4  TaskTextSummarisation        (IP-011)
;   5  TaskTranslation              (IP-012)
;   6  TaskDataExtraction           (IP-013)
;   7  ConversationalGreeting       (IP-020)
;   8  ConversationalAcknowledgement (IP-021)
;   9  SystemMetaQuery              (IP-030)
;  10  StructuredOutput             (IP-050)
;  11  AgenticToolUse               (IP-060)
;  12  ControlledCreative           (IP-099)
;
; Updated from 0..11 to 0..12 to include IP-060 (AgenticToolUse).
; The voter only checks intent equality — the range affects PO-V1/PO-V2 witnesses.

; ─── Type definitions ─────────────────────────────────────────────────────────

; Channel decision: what a single channel returns
(declare-datatypes () ((ChannelDecision
  (Pass (intent Int))   ; Pass with an intent ID (0..9 = 10 intents)
  (Block)
  (Fault)
)))

; Voter output
(declare-datatypes () ((VerdictKind
  VPass                 ; clean agreement on Pass
  VBlock                ; any block outcome
  VDiagnosticAgreement  ; both Pass, different intent — still Pass-class
  VDiagnosticDisagreement ; one Pass, one Block — Block-class
)))

; ─── Voter function ───────────────────────────────────────────────────────────
; Mirrors voter.rs::Voter::decide() exactly.

(define-fun voter ((a ChannelDecision) (b ChannelDecision)) VerdictKind
  (ite (is-Fault a) VBlock
  (ite (is-Fault b) VBlock
  (ite (and (is-Block a) (is-Block b)) VBlock
  (ite (and (is-Pass a) (is-Pass b))
       (ite (= (intent a) (intent b)) VPass VDiagnosticAgreement)
  ; one Pass, one Block
  VDiagnosticDisagreement)))))

; Helper: is the verdict Pass-class (i.e. prompt is allowed through)?
(define-fun is-pass-class ((v VerdictKind)) Bool
  (or (= v VPass) (= v VDiagnosticAgreement)))

; ─── PO-V1: Both Pass, same intent → VPass ───────────────────────────────────

(push)
(declare-const intent_x Int)
(assert (and (>= intent_x 0) (<= intent_x 12)))
(declare-const a1 ChannelDecision)
(declare-const b1 ChannelDecision)
(assert (= a1 (Pass intent_x)))
(assert (= b1 (Pass intent_x)))
; Claim: voter returns VPass. Negate and check UNSAT.
(assert (not (= (voter a1 b1) VPass)))
(check-sat) ; expected: unsat
(pop)

; ─── PO-V2: Both Pass, different intent → VDiagnosticAgreement ───────────────

(push)
(declare-const intent_p Int)
(declare-const intent_q Int)
(assert (and (>= intent_p 0) (<= intent_p 12)))
(assert (and (>= intent_q 0) (<= intent_q 12)))
(assert (not (= intent_p intent_q)))  ; different intents
(declare-const a2 ChannelDecision)
(declare-const b2 ChannelDecision)
(assert (= a2 (Pass intent_p)))
(assert (= b2 (Pass intent_q)))
; Claim: voter returns VDiagnosticAgreement. Negate and check UNSAT.
(assert (not (= (voter a2 b2) VDiagnosticAgreement)))
(check-sat) ; expected: unsat
(pop)

; ─── PO-V3: A=Pass, B=Block → VDiagnosticDisagreement (Block-class) ──────────

(push)
(declare-const intent_r Int)
(assert (and (>= intent_r 0) (<= intent_r 12)))
(declare-const a3 ChannelDecision)
(assert (= a3 (Pass intent_r)))
; Claim: voter returns VDiagnosticDisagreement. Negate and check UNSAT.
(assert (not (= (voter a3 Block) VDiagnosticDisagreement)))
(check-sat) ; expected: unsat
(pop)

; ─── PO-V4: A=Block, B=Pass → VDiagnosticDisagreement (Block-class) ──────────

(push)
(declare-const intent_s Int)
(assert (and (>= intent_s 0) (<= intent_s 12)))
(declare-const b4 ChannelDecision)
(assert (= b4 (Pass intent_s)))
; Claim: voter returns VDiagnosticDisagreement. Negate and check UNSAT.
(assert (not (= (voter Block b4) VDiagnosticDisagreement)))
(check-sat) ; expected: unsat
(pop)

; ─── PO-V5: Both Block → VBlock ──────────────────────────────────────────────

(push)
; Claim: voter(Block, Block) = VBlock. Negate and check UNSAT.
(assert (not (= (voter Block Block) VBlock)))
(check-sat) ; expected: unsat
(pop)

; ─── PO-V6: A=Fault → VBlock (fail-closed) ───────────────────────────────────

(push)
(declare-const b6 ChannelDecision)
; Claim: voter(Fault, anything) = VBlock. Negate and check UNSAT.
(assert (not (= (voter Fault b6) VBlock)))
(check-sat) ; expected: unsat
(pop)

; ─── PO-V7: B=Fault → VBlock (fail-closed) ───────────────────────────────────

(push)
(declare-const a7 ChannelDecision)
; Claim: voter(anything, Fault) = VBlock. Negate and check UNSAT.
(assert (not (= (voter a7 Fault) VBlock)))
(check-sat) ; expected: unsat
(pop)

; ─── PO-V8: Fail-closed invariant (global) ───────────────────────────────────
; The voter NEVER outputs a Pass-class verdict when either channel is Fault or Block.
; This is the core safety property: no single channel failure can cause a Pass.

(push)
(declare-const a8 ChannelDecision)
(declare-const b8 ChannelDecision)
; Precondition: at least one channel is NOT Pass
(assert (or (not (is-Pass a8)) (not (is-Pass b8))))
; Claim: verdict is never Pass-class. Negate and check UNSAT.
(assert (is-pass-class (voter a8 b8)))
(check-sat) ; expected: unsat
(pop)

; ─── PO-V9: DiagnosticDisagreement is always Block-class ─────────────────────
; Whenever the voter returns DiagnosticDisagreement, is-pass-class must be false.

(push)
(declare-const a9 ChannelDecision)
(declare-const b9 ChannelDecision)
(assert (= (voter a9 b9) VDiagnosticDisagreement))
; Claim: is-pass-class is false. Negate and check UNSAT.
(assert (is-pass-class (voter a9 b9)))
(check-sat) ; expected: unsat
(pop)

; ─── PO-V10: DiagnosticAgreement is always Pass-class ────────────────────────
; Whenever the voter returns DiagnosticAgreement, is-pass-class must be true.

(push)
(declare-const a10 ChannelDecision)
(declare-const b10 ChannelDecision)
(assert (= (voter a10 b10) VDiagnosticAgreement))
; Claim: is-pass-class is true. Negate and check UNSAT.
(assert (not (is-pass-class (voter a10 b10))))
(check-sat) ; expected: unsat
(pop)

(echo "All PO-V proof obligations checked.")
