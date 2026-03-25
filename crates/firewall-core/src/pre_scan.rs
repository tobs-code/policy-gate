// Diverse from the Unicode normalisation pipeline (types.rs::normalise()).
// Operates on raw UTF-8 bytes before any Unicode processing begins.
// Returns Some(detail) if a structural violation is found, None if clean.
//
// This is intentionally minimal — it only catches violations that are
// unambiguously malicious at the byte level and that normalise() might
// theoretically miss due to a Unicode edge case or future regression.
pub(crate) fn raw_byte_pre_scan(bytes: &[u8]) -> Option<String> {
    // Check 1: null byte — always malicious in a text prompt.
    if bytes.contains(&0x00) {
        return Some("raw null byte detected (SA-070)".into());
    }

    // Check 2: C0 control bytes (0x01–0x08, 0x0B–0x0C, 0x0E–0x1F) and DEL (0x7F).
    // Allowed: 0x09 (HT), 0x0A (LF), 0x0D (CR — normalised to LF downstream).
    // C1 range (0x80–0x9F) is valid UTF-8 continuation bytes in multi-byte sequences,
    // so we cannot blindly reject them here — that would break non-ASCII text.
    for &b in bytes {
        if matches!(b, 0x01..=0x08 | 0x0B..=0x0C | 0x0E..=0x1F | 0x7F) {
            return Some(format!("raw control byte 0x{b:02X} detected (SA-070)"));
        }
    }

    // Check 3: Known injection marker byte sequences (belt-and-suspenders for RE-002/FP-006).
    // These are ASCII-only sequences — safe to check at byte level without Unicode decoding.
    // We only include sequences that are unambiguously injection markers, not substrings
    // of legitimate text.
    const INJECTION_BYTE_MARKERS: &[&[u8]] = &[
        b"ignore previous instructions",
        b"ignore all prior",
        b"### new system prompt",
        b"<|im_start|>system",
        b"<|im_end|>",
        b"<|endoftext|>",
        b"<<sys>>",
        b"<</sys>>",
    ];
    let lower_bytes: Vec<u8> = bytes.iter().map(|b| b.to_ascii_lowercase()).collect();
    for marker in INJECTION_BYTE_MARKERS {
        if lower_bytes.windows(marker.len()).any(|w| w == *marker) {
            return Some("injection marker detected at byte level (SA-070)".into());
        }
    }

    None
}
