#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the normalisation pipeline: NFKC → NFD → strip Mn → NFC → confusables.
// Goal: no panics, no infinite loops, output is always valid UTF-8.
fuzz_target!(|data: &[u8]| {
    // Only feed valid UTF-8 — invalid bytes are not a normalisation concern.
    let Ok(s) = std::str::from_utf8(data) else { return };

    // PromptInput::new runs the full normalisation pipeline.
    // We only care that it never panics and always returns valid UTF-8.
    match firewall_core::PromptInput::new(s) {
        Ok(input) => {
            // Normalised text must be valid UTF-8 (Rust String guarantees this,
            // but we assert it explicitly as a fuzz oracle).
            assert!(std::str::from_utf8(input.text.as_bytes()).is_ok());
        }
        Err(_) => {
            // ExceededMaxLength is a valid, expected outcome — not a bug.
        }
    }
});
