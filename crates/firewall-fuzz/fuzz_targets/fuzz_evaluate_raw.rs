#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the full evaluation pipeline end-to-end.
// Goal: no panics, verdict is always well-formed, is_pass() is consistent
// with verdict_kind, audit entry is always populated.
fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };

    firewall_core::init().ok();
    let verdict = firewall_core::evaluate_raw(s, 0);

    // Invariant: is_pass() must be consistent with verdict_kind.
    use firewall_core::VerdictKind;
    let expected_pass = matches!(
        verdict.kind,
        VerdictKind::Pass | VerdictKind::DiagnosticAgreement
    );
    assert_eq!(verdict.is_pass(), expected_pass);

    // Invariant: block verdicts must always carry a block_reason.
    if !verdict.is_pass() {
        // DiagnosticAgreement is pass-class — no block_reason expected.
        if matches!(verdict.kind, VerdictKind::Block | VerdictKind::DiagnosticDisagreement) {
            assert!(
                verdict.audit.block_reason.is_some(),
                "Block verdict missing block_reason"
            );
        }
    }

    // Invariant: audit hash must always be non-empty.
    assert!(!verdict.audit.input_hash.is_empty());
});
