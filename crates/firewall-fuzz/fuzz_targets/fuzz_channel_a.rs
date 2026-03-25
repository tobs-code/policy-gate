#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz Channel A (FSM) in isolation.
// Goal: no panics, watchdog always fires within deadline,
// result is always one of Pass/Block/Fault.
fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };

    // Channel A operates on the normalised string directly.
    // Feed arbitrary UTF-8 — the FSM must handle anything without panicking.
    let result = firewall_core::fsm::ChannelA::evaluate(s);

    // Invariant: elapsed_us must be within watchdog budget (with margin).
    // WATCHDOG_DEADLINE_US is 500_000 µs in debug builds.
    assert!(
        result.elapsed_us < 600_000,
        "Channel A exceeded watchdog budget: {}µs",
        result.elapsed_us
    );
});
