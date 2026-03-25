// types.rs — canonical type definitions for the prompt firewall
// All types are designed for exhaustive pattern matching (no catch-all arms in safety code).

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
// Safety Action SA-003: Unicode NFKC normalisation — canonicalises homoglyph
// and decomposed-form attacks, AND compatibility characters (e.g. fullwidth
// ｍalware U+FF4D → malware) before any pattern matching occurs.
// NFKC is strictly stronger than NFC for security gates: it collapses
// compatibility equivalents that NFC leaves intact.
use unicode_normalization::UnicodeNormalization;

// ─── Input ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptInput {
    pub text: String,
    pub role: Option<String>,
    pub ingested_at_ns: u128,
    /// SA-048: Set to true if Unicode Format (Cf) or visual-spoofing characters
    /// were detected and stripped during normalisation.
    pub has_obfuscation: bool,
}

impl PromptInput {
    /// Normalise and construct a PromptInput.
    /// Returns `Err(BlockReason::ExceededMaxLength)` if the input exceeds 8192 bytes
    /// after NFC normalisation and trimming (SA-010: hard reject, no silent truncation).
    pub fn new(raw: impl Into<String>) -> Result<Self, BlockReason> {
        let raw = raw.into();
        // Capture ingested_at_ns BEFORE normalisation so the timestamp reflects
        // the moment the raw input arrived. Normalisation (NFKC, combining-strip,
        // confusables, size-check) can take measurable time on long inputs and
        // should be included in total_elapsed_us for accurate latency accounting.
        let ingested_at_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos();
        let (text, has_obfuscation) = Self::normalise_text(&raw)?;
        Ok(Self {
            text,
            role: None,
            ingested_at_ns,
            has_obfuscation,
        })
    }

    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }

    pub fn normalise_text(raw: &str) -> Result<(String, bool), BlockReason> {
        // Step 0: CRLF → LF normalisation (SA-035).
        // \r (U+000D) is not blocked by Init (range 11..=12 skips 13) so
        // "---\r\nsystem:" survives Init and Tokenizing intact, bypassing
        // FP-006 which searches for "---\nsystem:" as a substring.
        // Replacing \r\n → \n and bare \r → \n before any other step closes
        // this gap without blocking legitimate Windows line endings.
        let raw_normalised_crlf;
        let raw: &str = if raw.contains('\r') {
            raw_normalised_crlf = raw.replace("\r\n", "\n").replace('\r', "\n");
            &raw_normalised_crlf
        } else {
            raw
        };

        // Step 0b: Pre-NFKC raw byte limit (SA-044 / H-15).
        // Certain Unicode codepoints expand dramatically under NFKC normalisation
        // (e.g. U+FDFB expands to 18 characters). An attacker can craft a payload
        // of ~2730 × U+FDFB (8 190 raw bytes) that forces ~49 KB of NFKC work
        // before the post-NFKC size check in Step 4 fires. This is a DoS vector:
        // the pipeline pays full normalisation cost for inputs that will be
        // rejected anyway.
        //
        // Mitigation: hard-reject inputs whose raw byte length already exceeds
        // the post-NFKC limit. A legitimate prompt that fits within 8 192 bytes
        // after normalisation cannot exceed 8 192 raw bytes (normalisation never
        // increases byte length beyond the expansion factor, and any input that
        // would expand beyond the limit is malicious by construction).
        //
        // This check is intentionally identical to the post-NFKC limit (Step 4)
        // so that the two limits form a consistent pair. It does NOT replace
        // Step 4 — Step 4 remains the authoritative check on the normalised form.
        if raw.len() > 8_192 {
            return Err(BlockReason::ExceededMaxLength);
        }

        // Step 1: Unicode NFKC normalisation (SA-003).
        // NFKC is used instead of NFC because it additionally collapses
        // compatibility characters — e.g. fullwidth Latin ｍalware (U+FF4D…)
        // becomes "malware", preventing homoglyph bypass of FP-003/FP-004.
        // NFC only handles canonical decomposition; NFKC handles both canonical
        // and compatibility decomposition. For a security gate this is the
        // correct choice: we prefer false-positive safety over preserving
        // exotic Unicode forms.
        let nfkc: String = raw.nfkc().collect();

        // Step 2: Strip Unicode Non-Spacing Marks / Combining Characters (SA-029)
        //         and Variation Selectors (SA-031).
        //
        // Zalgo-style attacks stack combining diacritics on top of ASCII letters
        // to visually obscure keywords: "m̀álŵãr̅ȇ" contains "malware" but
        // FP-003 substring search would not find it.
        // We strip all codepoints in Unicode General Category Mn (Non-Spacing Mark)
        // by checking the well-known stable codepoint ranges. This is deterministic
        // and requires no additional crate.
        //
        // CRITICAL ORDER (SA-038): NFKC in Step 1 composes combining marks into
        // precomposed characters BEFORE Step 2 can strip them.
        // Example: 'a' + U+0300 (Combining Grave) → NFKC → 'à' (U+00E0, precomposed).
        // Step 2 then finds no combining marks to strip — 'à' is not in Mn ranges.
        // Fix: after NFKC, apply NFD decomposition to re-expose combining marks,
        // strip them, then recompose with NFC.
        // Pipeline: raw → NFKC → NFD → strip Mn → NFC
        // This correctly reduces "m̀álŵãrȅ" → "malware".
        //
        // Ranges covered (Unicode 15, stable):
        //   U+0300–U+036F  Combining Diacritical Marks
        //   U+0483–U+0489  Combining Cyrillic marks
        //   U+0591–U+05BD  Hebrew points
        //   U+0610–U+061A  Arabic extended
        //   U+064B–U+065F  Arabic diacritics (tashkeel)
        //   U+1AB0–U+1AFF  Combining Diacritical Marks Extended
        //   U+1DC0–U+1DFF  Combining Diacritical Marks Supplement
        //   U+20D0–U+20FF  Combining Diacritical Marks for Symbols
        //   U+FE20–U+FE2F  Combining Half Marks
        //
        // SA-031: Variation Selectors (U+FE00–U+FE0F, U+E0100–U+E01EF) and
        // Unicode Format (Cf) characters (e.g. Zero Width Space, Bidi marks)
        // are also stripped here. These are invisible or non-spacing codepoints
        // that NFKC does not remove — "mal\u{200B}ware" would bypass FP-003
        // without this step.
        // bypass FP-003 substring matching. Stripping them closes this gap.
        let mut has_obfuscation = false;
        let nfd_stripped: String = nfkc
            .nfd()
            .filter(|&c| {
                if is_obfuscation_character(c) {
                    has_obfuscation = true;
                    return false;
                }
                !is_combining_mark(c)
            })
            .collect();
        // Recompose to NFC so the result is in a canonical composed form.
        let stripped: String = nfd_stripped.nfc().collect();

        // Step 3: Confusables normalisation (SA-029).
        // Maps visually similar non-ASCII codepoints to their ASCII equivalents.
        // Targets the Cyrillic/Greek/Latin-Extended homoglyph attack:
        //   "mаlwаre" (Cyrillic а U+0430) → "malware" (Latin a U+0061)
        // Only maps codepoints that are visually indistinguishable from ASCII
        // a-z/0-9 in common fonts. Does NOT map characters with distinct visual
        // appearance (e.g. Cyrillic Д is not mapped — it doesn't look like D).
        // Table derived from Unicode TR39 confusables.txt, filtered to ASCII target.
        let confusable_normalised: String = stripped.chars().map(confusable_to_ascii).collect();

        // Step 3b: Separator-strip (SA-045).
        // Attackers insert punctuation between keyword letters to split substring
        // matching: "m.a.l.w.a.r.e" bypasses simple checks.
        //
        // Refinement (Gap 4): Instead of stripping every intra-word separator (which
        // collapses legitimate terms like "API-Key"), we only strip if:
        //   1. There are MULTIPLE separators in a short window (e.g., "m.a.l").
        //   2. The separator is REPEATED (e.g., "m---a").
        //
        // Implementation: identify "obfuscation runs" and collapse them.
        let separator_stripped: String = {
            let chars: Vec<char> = confusable_normalised.chars().collect();
            let mut out = String::with_capacity(chars.len());
            let mut i = 0;
            while i < chars.len() {
                let c = chars[i];
                if (c == '-'
                    || c == '.'
                    || c == '_'
                    || c == ','
                    || c == ';'
                    || c == ':'
                    || c == '!'
                    || c == '/'
                    || c == '~')
                    && i > 0
                    && i + 1 < chars.len()
                    && chars[i - 1].is_ascii_alphanumeric()
                    && chars[i + 1].is_ascii_alphanumeric()
                {
                    // Look around to see if this is an "obfuscation sequence"
                    // FIXED: Limit word context scan to ±8 characters and check for excessive segmentation
                    let mut start = i;
                    while start > 0
                        && (chars[start - 1].is_ascii_alphanumeric()
                            || "-._,:;!/~".contains(chars[start - 1]))
                        && i - start < 8
                    {
                        start -= 1;
                    }
                    let mut end = i;
                    while end + 1 < chars.len()
                        && (chars[end + 1].is_ascii_alphanumeric()
                            || "-._,:;!/~".contains(chars[end + 1]))
                        && end - i < 8
                    {
                        end += 1;
                    }

                    // Count alphanumeric segments and separators in the limited context
                    let mut segment_count = 0;
                    let mut separator_count = 0;
                    let mut in_segment = false;

                    for ch in chars.iter().take(end + 1).skip(start) {
                        if ch.is_ascii_alphanumeric() {
                            if !in_segment {
                                segment_count += 1;
                                in_segment = true;
                            }
                        } else if "-._,:;!/~".contains(*ch) {
                            separator_count += 1;
                            in_segment = false;
                        } else {
                            in_segment = false;
                        }
                    }

                    // Strip if excessive segmentation: many short segments with separators
                    // This catches "m/a/l/w/a/r/e" (6 segments, 5 separators) but preserves
                    // "API/Key/v2.1" (4 segments, 3 separators) and "API-Key" (2 segments, 1 separator)
                    if segment_count > 4 && separator_count > 3 {
                        i += 1;
                        continue;
                    }
                }
                out.push(c);
                i += 1;
            }
            out
        };

        // Step 3c: Multiple space collapse (SA-045).
        // Collapse multiple whitespace runs into a single space to prevent
        // manual whitespace splits from bypassing simple substring checks.
        let space_collapsed: String = {
            let mut result = String::with_capacity(separator_stripped.len());
            let mut last_was_space = false;
            for c in separator_stripped.chars() {
                if c.is_whitespace() {
                    if !last_was_space {
                        result.push(' ');
                        last_was_space = true;
                    }
                } else {
                    result.push(c);
                    last_was_space = false;
                }
            }
            result
        };

        let trimmed = space_collapsed.trim();

        // Step 3d: Explicit empty/whitespace handling (SA-072).
        // Empty strings after trimming are treated as fail-closed:
        // They flow to Channel A/B → NoIntentMatch → Block (fail-closed security model).
        // This is documented behavior: empty input cannot satisfy any safe intent.
        if trimmed.is_empty() {
            // Return empty string - will result in Block verdict downstream
            return Ok((String::new(), has_obfuscation));
        }

        // Step 4: Multilingual Translation (DC-GAP-07 / SA-049).
        // Deterministic keyword translation for common non-English framing words
        // to handle basic safe intents (German, French, Spanish).
        // This is a strictly limited, deterministic set — no complex ML.
        let translated: String = {
            let mut result = trimmed.to_string();
            const TRANSLATION_MAP: &[(&str, &str)] = &[
                // German
                ("wer ist ", "who is "),
                ("was ist ", "what is "),
                ("wo ist ", "where is "),
                ("wann ist ", "when is "),
                ("warum ist ", "why is "),
                ("wie ist ", "how is "),
                ("welche ist ", "which is "),
                ("übersetze ", "translate "),
                ("fasse zusammen ", "summarize "),
                // Gap-15.4 Fix: Multilingual Legal/Educational Framing
                (
                    "für eine wissenschaftliche arbeit ",
                    "for a scientific paper ",
                ),
                ("für meine arbeit ", "for my work "),
                ("theoretisch ", "theoretically "),
                ("rein hypothetisch ", "purely hypothetical "),
                ("nur für bildungszwecke ", "only for educational purposes "),
                ("im kontext von ", "in the context of "),
                ("als beispiel ", "as an example "),
                // French
                ("qui est ", "who is "),
                ("qu'est-ce que ", "what is "),
                ("où est ", "where is "),
                ("quand est ", "when is "),
                ("pourquoi ", "why "),
                ("comment ", "how "),
                ("quel est ", "which is "),
                ("traduisez ", "translate "),
                ("résumez ", "summarize "),
                // Gap-15.4 Fix: French Legal/Educational Framing
                ("pour un travail scientifique ", "for a scientific paper "),
                ("pour mon travail ", "for my work "),
                ("théoriquement ", "theoretically "),
                ("purement hypothétique ", "purely hypothetical "),
                (
                    "uniquement à des fins éducatives ",
                    "only for educational purposes ",
                ),
                ("dans le contexte de ", "in the context of "),
                ("à titre d'exemple ", "as an example "),
                // Spanish
                ("quién es ", "who is "),
                ("quien es ", "who is "),
                ("¿quién es ", "who is "),
                ("¿quien es ", "who is "),
                ("qué es ", "who is "),
                ("que es ", "who is "),
                ("¿qué es ", "who is "),
                ("¿que es ", "who is "),
                ("dónde está ", "where is "),
                ("donde esta ", "where is "),
                ("¿dónde está ", "where is "),
                ("¿donde esta ", "where is "),
                ("cuándo es ", "when is "),
                ("cuando es ", "when is "),
                ("¿cuándo es ", "when is "),
                ("¿cuando es ", "when is "),
                ("por qué ", "why "),
                ("por que ", "why "),
                ("¿por qué ", "why "),
                ("¿por que ", "why "),
                ("cómo ", "how "),
                ("como ", "how "),
                ("¿cómo ", "how "),
                ("¿como ", "how "),
                ("cuál es ", "which is "),
                ("cual es ", "which is "),
                ("¿cuál es ", "which is "),
                ("¿cual es ", "which is "),
                ("traduce ", "translate "),
                ("resume ", "summarize "),
                // Gap-15.4 Fix: Spanish Legal/Educational Framing
                ("para un trabajo científico ", "for a scientific paper "),
                ("para mi trabajo ", "for my work "),
                ("teóricamente ", "theoretically "),
                ("puramente hipotético ", "purely hypothetical "),
                (
                    "solo con fines educativos ",
                    "only for educational purposes ",
                ),
                ("en el contexto de ", "in the context of "),
                ("como ejemplo ", "as an example "),
            ];
            let lower = result.to_lowercase();
            for (from, to) in TRANSLATION_MAP {
                if lower.starts_with(from) {
                    result = format!("{}{}", to, &result[from.len()..]);
                    break;
                }
            }
            result
        };

        // Step 5: Hard reject inputs exceeding 8192 bytes (SA-010).
        if translated.len() > 8_192 {
            return Err(BlockReason::ExceededMaxLength);
        }
        Ok((translated, has_obfuscation))
    }
}

// ─── SA-029 / SA-048: Legitimate healing characters ──────────────────────────

/// Returns true if the codepoint is a Unicode Non-Spacing Mark (Mn)
/// or a Variation Selector (SA-031). These characters are stripped to
/// "heal" the input so that keywords can be matched (SA-029).
/// They are NOT considered obfuscation (has_obfuscation = false).
#[inline]
fn is_combining_mark(c: char) -> bool {
    let cp = c as u32;
    matches!(cp,
        0x0300..=0x036F |  // Combining Diacritical Marks
        0x0483..=0x0489 |  // Combining Cyrillic marks
        0x0591..=0x05BD |  // Hebrew points
        0x05BF..=0x05BF |  // Hebrew point Rafe
        0x05C1..=0x05C2 |  // Hebrew shin/sin dot
        0x05C4..=0x05C5 |  // Hebrew upper/lower dot
        0x05C7..=0x05C7 |  // Hebrew qamats qatan
        0x0610..=0x061A |  // Arabic extended
        0x064B..=0x065F |  // Arabic tashkeel
        0x0670..=0x0670 |  // Arabic letter superscript alef
        0x06D6..=0x06DC |  // Arabic small high letters
        0x06DF..=0x06E4 |  // Arabic small high letters (cont.)
        0x06E7..=0x06E8 |  // Arabic small high yeh/noon
        0x06EA..=0x06ED |  // Arabic empty centre/high stops
        0x0711..=0x0711 |  // Syriac letter superscript alaph
        0x0730..=0x074A |  // Syriac combining marks
        0x07A6..=0x07B0 |  // Thaana combining marks
        0x07EB..=0x07F3 |  // NKo combining marks
        0x0816..=0x082D |  // Samaritan combining marks
        0x0859..=0x085B |  // Mandaic combining marks
        0x08D3..=0x08E1 |  // Arabic extended-A combining
        0x08E3..=0x08FF |  // Arabic extended-A combining (cont.)
        0x0900..=0x0902 |  // Devanagari combining (vowel signs above)
        0x093A..=0x093A |  // Devanagari vowel sign OE
        0x093C..=0x093C |  // Devanagari nukta
        0x0941..=0x0948 |  // Devanagari vowel signs
        0x094D..=0x094D |  // Devanagari virama
        0x0951..=0x0957 |  // Devanagari stress/tone marks
        0x0962..=0x0963 |  // Devanagari vowel signs (vocalic)
        0x0981..=0x0981 |  // Bengali sign anusvara
        0x09BC..=0x09BC |  // Bengali nukta
        0x09C1..=0x09C4 |  // Bengali vowel signs
        0x09CD..=0x09CD |  // Bengali virama
        0x09E2..=0x09E3 |  // Bengali vowel signs (vocalic)
        0x0A01..=0x0A02 |  // Gurmukhi signs
        0x0A3C..=0x0A3C |  // Gurmukhi nukta
        0x0A41..=0x0A42 |  // Gurmukhi vowel signs
        0x0A47..=0x0A48 |  // Gurmukhi vowel signs
        0x0A4B..=0x0A4D |  // Gurmukhi vowel signs / virama
        0x0A51..=0x0A51 |  // Gurmukhi sign udaat
        0x0A70..=0x0A71 |  // Gurmukhi tippi/addak
        0x0A75..=0x0A75 |  // Gurmukhi yakash
        0x0A81..=0x0A82 |  // Gujarati signs
        0x0ABC..=0x0ABC |  // Gujarati nukta
        0x0AC1..=0x0AC5 |  // Gujarati vowel signs
        0x0AC7..=0x0AC8 |  // Gujarati vowel signs
        0x0ACD..=0x0ACD |  // Gujarati virama
        0x0AE2..=0x0AE3 |  // Gujarati vowel signs (vocalic)
        0x0AFA..=0x0AFF |  // Gujarati combining marks
        0x0B01..=0x0B01 |  // Oriya sign candrabindu
        0x0B3C..=0x0B3C |  // Oriya nukta
        0x0B3F..=0x0B3F |  // Oriya vowel sign I
        0x0B41..=0x0B44 |  // Oriya vowel signs
        0x0B4D..=0x0B4D |  // Oriya virama
        0x0B55..=0x0B56 |  // Oriya signs
        0x0B62..=0x0B63 |  // Oriya vowel signs (vocalic)
        0x0B82..=0x0B82 |  // Tamil sign anusvara
        0x0BC0..=0x0BC0 |  // Tamil vowel sign II
        0x0BCD..=0x0BCD |  // Tamil virama
        0x0C00..=0x0C00 |  // Telugu sign combining candrabindu
        0x0C04..=0x0C04 |  // Telugu sign combining anusvara above
        0x0C3E..=0x0C40 |  // Telugu vowel signs
        0x0C46..=0x0C48 |  // Telugu vowel signs
        0x0C4A..=0x0C4D |  // Telugu vowel signs / virama
        0x0C55..=0x0C56 |  // Telugu length marks
        0x0C62..=0x0C63 |  // Telugu vowel signs (vocalic)
        0x0C81..=0x0C81 |  // Kannada sign candrabindu
        0x0CBC..=0x0CBC |  // Kannada nukta
        0x0CBF..=0x0CBF |  // Kannada vowel sign I
        0x0CC6..=0x0CC6 |  // Kannada vowel sign E
        0x0CCC..=0x0CCD |  // Kannada vowel signs / virama
        0x0CE2..=0x0CE3 |  // Kannada vowel signs (vocalic)
        0x0D00..=0x0D01 |  // Malayalam signs
        0x0D3B..=0x0D3C |  // Malayalam signs
        0x0D41..=0x0D44 |  // Malayalam vowel signs
        0x0D4D..=0x0D4D |  // Malayalam virama
        0x0D62..=0x0D63 |  // Malayalam vowel signs (vocalic)
        0x0D81..=0x0D81 |  // Sinhala sign candrabindu
        0x0DCA..=0x0DCA |  // Sinhala virama
        0x0DD2..=0x0DD4 |  // Sinhala vowel signs
        0x0DD6..=0x0DD6 |  // Sinhala vowel sign diga paa-pilla
        0x0E31..=0x0E31 |  // Thai character mai han akat
        0x0E34..=0x0E3A |  // Thai vowel signs / sara
        0x0E47..=0x0E4E |  // Thai tone marks / thanthakat
        0x0EB1..=0x0EB1 |  // Lao vowel sign mai kan
        0x0EB4..=0x0EBC |  // Lao vowel signs / semivowel
        0x0EC8..=0x0ECD |  // Lao tone marks
        0x0F71..=0x0F7E |  // Tibetan vowel signs
        0x0F80..=0x0F84 |  // Tibetan vowel signs (cont.)
        0x0F86..=0x0F87 |  // Tibetan sign lci rtags / yang rtags
        0x302A..=0x302F |  // CJK ideographic description combining marks
        0x3099..=0x309A |  // Combining katakana-hiragana voiced/semi-voiced mark
        0x1AB0..=0x1AFF |  // Combining Diacritical Marks Extended
        0x1DC0..=0x1DFF |  // Combining Diacritical Marks Supplement
        0x20D0..=0x20FF |  // Combining Diacritical Marks for Symbols
        0xFE00..=0xFE0F |  // Variation Selectors (SA-031)
        0xFE20..=0xFE2F |  // Combining Half Marks
        0xE0100..=0xE01EF   // Variation Selectors Supplement (SA-031)
    )
}

// ─── SA-048: Suspicious obfuscation characters ────────────────────────────────

/// Returns true if the codepoint is a Unicode Format (Cf) or visual-spoofing
/// character. These are stripped to catch keywords, but they trigger
/// has_obfuscation = true (SA-048).
#[inline]
fn is_obfuscation_character(c: char) -> bool {
    let cp = c as u32;
    matches!(cp,
        0x00AD..=0x00AD |  // Soft Hyphen
        0x061C..=0x061C |  // Arabic Letter Mark
        0x115F..=0x1160 |  // Hangul filler (common ZW-variant)
        0x200B..=0x200F |  // Zero Width Space, ZWNJ, ZWJ, LRM, RLM
        0x202A..=0x202E |  // LRE, RLE, PDF, LRO, RLO (Bidi overrides)
        0x2060..=0x206F |  // Word Joiner, Format characters
        0xFEFF..=0xFEFF |  // Byte Order Mark / ZW Non-Breaking Space
        0xE0001..=0xE0001 | // Language Tag (Cf)
        0xE0020..=0xE007F   // Tagging characters
    )
}

// ─── SA-029: Confusables table ────────────────────────────────────────────────

/// Maps visually confusable non-ASCII codepoints to their ASCII equivalents.
/// Derived from Unicode TR39 confusables.txt, filtered to codepoints that are
/// visually indistinguishable from ASCII a-z / 0-9 in common Latin-script fonts.
///
/// Coverage: Cyrillic, Greek, Latin Extended, Mathematical Alphanumerics,
/// Letterlike Symbols — the most common homoglyph attack vectors.
#[inline]
fn confusable_to_ascii(c: char) -> char {
    match c {
        // ── Cyrillic lookalikes ───────────────────────────────────────────────
        // These are the primary attack vector: Cyrillic letters that are
        // visually identical to Latin letters in most fonts.
        'а' => 'a', // U+0430 CYRILLIC SMALL LETTER A
        'е' => 'e', // U+0435 CYRILLIC SMALL LETTER IE
        'о' => 'o', // U+043E CYRILLIC SMALL LETTER O
        'р' => 'p', // U+0440 CYRILLIC SMALL LETTER ER
        'с' => 'c', // U+0441 CYRILLIC SMALL LETTER ES
        'х' => 'x', // U+0445 CYRILLIC SMALL LETTER HA
        'у' => 'y', // U+0443 CYRILLIC SMALL LETTER U
        'ѕ' => 's', // U+0455 CYRILLIC SMALL LETTER DZE
        'і' => 'i', // U+0456 CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
        'ј' => 'j', // U+0458 CYRILLIC SMALL LETTER JE
        'ԁ' => 'd', // U+0501 CYRILLIC SMALL LETTER KOMI DE
        'ԛ' => 'q', // U+051B CYRILLIC SMALL LETTER QA
        'ԝ' => 'w', // U+051D CYRILLIC SMALL LETTER WE
        'А' => 'A', // U+0410 CYRILLIC CAPITAL LETTER A
        'В' => 'B', // U+0412 CYRILLIC CAPITAL LETTER VE
        'Е' => 'E', // U+0415 CYRILLIC CAPITAL LETTER IE
        'К' => 'K', // U+041A CYRILLIC CAPITAL LETTER KA
        'М' => 'M', // U+041C CYRILLIC CAPITAL LETTER EM
        'Н' => 'H', // U+041D CYRILLIC CAPITAL LETTER EN
        'О' => 'O', // U+041E CYRILLIC CAPITAL LETTER O
        'Р' => 'P', // U+0420 CYRILLIC CAPITAL LETTER ER
        'С' => 'C', // U+0421 CYRILLIC CAPITAL LETTER ES
        'Т' => 'T', // U+0422 CYRILLIC CAPITAL LETTER TE
        'Х' => 'X', // U+0425 CYRILLIC CAPITAL LETTER HA
        // ── Greek lookalikes ──────────────────────────────────────────────────
        'α' => 'a', // U+03B1 GREEK SMALL LETTER ALPHA
        'ε' => 'e', // U+03B5 GREEK SMALL LETTER EPSILON
        'ο' => 'o', // U+03BF GREEK SMALL LETTER OMICRON
        'ν' => 'v', // U+03BD GREEK SMALL LETTER NU
        'χ' => 'x', // U+03C7 GREEK SMALL LETTER CHI
        'ρ' => 'p', // U+03C1 GREEK SMALL LETTER RHO
        'ϲ' => 'c', // U+03F2 GREEK LUNATE SIGMA SYMBOL
        'Α' => 'A', // U+0391 GREEK CAPITAL LETTER ALPHA
        'Β' => 'B', // U+0392 GREEK CAPITAL LETTER BETA
        'Ε' => 'E', // U+0395 GREEK CAPITAL LETTER EPSILON
        'Η' => 'H', // U+0397 GREEK CAPITAL LETTER ETA
        'Ι' => 'I', // U+0399 GREEK CAPITAL LETTER IOTA
        'Κ' => 'K', // U+039A GREEK CAPITAL LETTER KAPPA
        'Μ' => 'M', // U+039C GREEK CAPITAL LETTER MU
        'Ν' => 'N', // U+039D GREEK CAPITAL LETTER NU
        'Ο' => 'O', // U+039F GREEK CAPITAL LETTER OMICRON
        'Ρ' => 'P', // U+03A1 GREEK CAPITAL LETTER RHO
        'Τ' => 'T', // U+03A4 GREEK CAPITAL LETTER TAU
        'Υ' => 'Y', // U+03A5 GREEK CAPITAL LETTER UPSILON
        'Χ' => 'X', // U+03A7 GREEK CAPITAL LETTER CHI
        'Ζ' => 'Z', // U+0396 GREEK CAPITAL LETTER ZETA
        // ── Latin Extended / IPA lookalikes ───────────────────────────────────
        'ɑ' => 'a', // U+0251 LATIN SMALL LETTER ALPHA
        'ɡ' => 'g', // U+0261 LATIN SMALL LETTER SCRIPT G
        'ɩ' => 'i', // U+0269 LATIN SMALL LETTER IOTA
        'ɾ' => 'r', // U+027E LATIN SMALL LETTER R WITH FISHHOOK
        'ʋ' => 'v', // U+028B LATIN SMALL LETTER V WITH HOOK
        // ── Latin Small Capital letters (Unicode TR39 confusables) ────────────
        // These are visually indistinguishable from lowercase ASCII in most fonts
        // and are used in obfuscation attacks (e.g. "ᴍalware", "ꜱhellcode").
        'ʜ' => 'h', // U+029C LATIN LETTER SMALL CAPITAL H
        'ɪ' => 'i', // U+026A LATIN LETTER SMALL CAPITAL I
        'ʟ' => 'l', // U+029F LATIN LETTER SMALL CAPITAL L
        'ɴ' => 'n', // U+0274 LATIN LETTER SMALL CAPITAL N
        'ʀ' => 'r', // U+0280 LATIN LETTER SMALL CAPITAL R
        'ʏ' => 'y', // U+028F LATIN LETTER SMALL CAPITAL Y
        'ᴀ' => 'a', // U+1D00 LATIN LETTER SMALL CAPITAL A
        'ʙ' => 'b', // U+0299 LATIN LETTER SMALL CAPITAL B
        'ᴄ' => 'c', // U+1D04 LATIN LETTER SMALL CAPITAL C
        'ᴅ' => 'd', // U+1D05 LATIN LETTER SMALL CAPITAL D
        'ᴇ' => 'e', // U+1D07 LATIN LETTER SMALL CAPITAL E
        'ɢ' => 'g', // U+0262 LATIN LETTER SMALL CAPITAL G
        'ᴊ' => 'j', // U+1D0A LATIN LETTER SMALL CAPITAL J
        'ᴋ' => 'k', // U+1D0B LATIN LETTER SMALL CAPITAL K
        'ᴍ' => 'm', // U+1D0D LATIN LETTER SMALL CAPITAL M
        'ᴏ' => 'o', // U+1D0F LATIN LETTER SMALL CAPITAL O
        'ᴘ' => 'p', // U+1D18 LATIN LETTER SMALL CAPITAL P
        'ꜱ' => 's', // U+A731 LATIN LETTER SMALL CAPITAL S
        'ᴛ' => 't', // U+1D1B LATIN LETTER SMALL CAPITAL T
        'ᴜ' => 'u', // U+1D1C LATIN LETTER SMALL CAPITAL U
        'ᴠ' => 'v', // U+1D20 LATIN LETTER SMALL CAPITAL V
        'ᴡ' => 'w', // U+1D21 LATIN LETTER SMALL CAPITAL W
        'ᴢ' => 'z', // U+1D22 LATIN LETTER SMALL CAPITAL Z
        'ꜰ' => 'f', // U+A730 LATIN LETTER SMALL CAPITAL F
        // ── Letterlike Symbols ────────────────────────────────────────────────
        'ℬ' => 'B', // U+212C SCRIPT CAPITAL B
        // ── Leet-speak digit substitutions (SA-045) ───────────────────────────
        // Attackers substitute ASCII digits for visually similar letters to bypass
        // keyword matching: "m4lw4re", "sh3llc0de", "r00tk1t", "b4ckd00r".
        // Map the digits to their letter equivalents so FP-003/RE-004 can match.
        //
        // ⚠ FALSE-POSITIVE WARNING: This mapping is aggressive. All ASCII digits
        // 0–9 are remapped, which means numeric strings in otherwise legitimate
        // prompts are also transformed (e.g. "hello123" → "hellolze").
        // This is intentional: the normalised form is only used for FP-003/RE-004
        // keyword matching, never returned to the caller. The trade-off is accepted
        // because leet-speak obfuscation is a real attack vector and the FP risk
        // on the keyword-match path is low (legitimate prompts rarely contain
        // digit-substituted attack keywords). Operators who observe unexpected
        // blocks on numeric content should review FP-003/RE-004 keyword lists.
        //
        // Full mapping: '0'→'o', '1'→'l', '2'→'z', '3'→'e', '4'→'a', '5'→'s',
        //               '6'→'g', '7'→'t', '8'→'b', '9'→'g', '@'→'a', '$'→'s', '|'→'l'
        '0' => 'o',
        '1' => 'l', // changed from 'i' to 'l' (IP-045: malware, shellcode bypasses '1'->'i')
        '2' => 'z',
        '3' => 'e',
        '4' => 'a',
        '5' => 's',
        '7' => 't',
        '8' => 'b',
        '9' => 'g',
        '@' => 'a',
        '$' => 's',
        '|' => 'l',
        '6' => 'g',
        'ℰ' => 'E', // U+2130 SCRIPT CAPITAL E
        'ℱ' => 'F', // U+2131 SCRIPT CAPITAL F
        'ℋ' => 'H', // U+210B SCRIPT CAPITAL H
        'ℐ' => 'I', // U+2110 SCRIPT CAPITAL I
        'ℒ' => 'L', // U+2112 SCRIPT CAPITAL L
        'ℳ' => 'M', // U+2133 SCRIPT CAPITAL M
        'ℛ' => 'R', // U+211B SCRIPT CAPITAL R
        'ℯ' => 'e', // U+212F SCRIPT SMALL E
        'ℊ' => 'g', // U+210A SCRIPT SMALL G
        'ℴ' => 'o', // U+2134 SCRIPT SMALL O
        'ℓ' => 'l', // U+2113 SCRIPT SMALL L (e.g. "sheℓℓcode")
        // ── Mathematical Alphanumerics (common in obfuscation) ────────────────
        // Bold, italic, script variants of a-z — all map to their ASCII base.
        // Ranges: U+1D400–U+1D7FF (Mathematical Alphanumeric Symbols)
        // Handled by the range-based fallback below.
        _ => math_alnum_to_ascii(c),
    }
}

/// Maps Mathematical Alphanumeric Symbols (U+1D400–U+1D7FF) to ASCII.
/// These are bold/italic/script/fraktur/double-struck/monospace variants of a-z/A-Z/0-9.
/// NFKC already handles most of these, but this is a belt-and-suspenders check.
///
/// Note on unassigned slots: several codepoints in these ranges are unassigned
/// (Unicode uses them for special letters like ℎ, ℯ etc. which are in the
/// Letterlike Symbols block instead). For unassigned slots we return `c` unchanged —
/// NFKC will have already handled any assigned compatibility equivalents.
#[inline]
fn math_alnum_to_ascii(c: char) -> char {
    let cp = c as u32;
    match cp {
        // ── Bold (U+1D400–U+1D433) ────────────────────────────────────────────
        0x1D400..=0x1D419 => char::from_u32('A' as u32 + (cp - 0x1D400)).unwrap_or(c),
        0x1D41A..=0x1D433 => char::from_u32('a' as u32 + (cp - 0x1D41A)).unwrap_or(c),
        // ── Italic (U+1D434–U+1D467; U+1D455 unassigned) ─────────────────────
        0x1D434..=0x1D44D => char::from_u32('A' as u32 + (cp - 0x1D434)).unwrap_or(c),
        0x1D455 => c, // unassigned (ℎ is U+210E, handled in confusable_to_ascii)
        0x1D44E..=0x1D467 => char::from_u32('a' as u32 + (cp - 0x1D44E)).unwrap_or(c),
        // ── Bold Italic (U+1D468–U+1D49B) ────────────────────────────────────
        0x1D468..=0x1D481 => char::from_u32('A' as u32 + (cp - 0x1D468)).unwrap_or(c),
        0x1D482..=0x1D49B => char::from_u32('a' as u32 + (cp - 0x1D482)).unwrap_or(c),
        // ── Script (U+1D49C–U+1D4CF; several slots unassigned — in Letterlike) ─
        // Assigned capital slots: map to A-Z; unassigned slots return c (NFKC handled).
        0x1D49C => 'A', // MATHEMATICAL SCRIPT CAPITAL A
        0x1D49E => 'C', // MATHEMATICAL SCRIPT CAPITAL C
        0x1D49F => 'D', // MATHEMATICAL SCRIPT CAPITAL D
        0x1D4A2 => 'G', // MATHEMATICAL SCRIPT CAPITAL G
        0x1D4A5 => 'J', // MATHEMATICAL SCRIPT CAPITAL J
        0x1D4A6 => 'K', // MATHEMATICAL SCRIPT CAPITAL K
        0x1D4A9 => 'N', // MATHEMATICAL SCRIPT CAPITAL N
        0x1D4AA => 'O', // MATHEMATICAL SCRIPT CAPITAL O
        0x1D4AB => 'P', // MATHEMATICAL SCRIPT CAPITAL P
        0x1D4AC => 'Q', // MATHEMATICAL SCRIPT CAPITAL Q
        0x1D4AE => 'S', // MATHEMATICAL SCRIPT CAPITAL S
        0x1D4AF => 'T', // MATHEMATICAL SCRIPT CAPITAL T
        0x1D4B0 => 'U', // MATHEMATICAL SCRIPT CAPITAL U
        0x1D4B1 => 'V', // MATHEMATICAL SCRIPT CAPITAL V
        0x1D4B2 => 'W', // MATHEMATICAL SCRIPT CAPITAL W
        0x1D4B3 => 'X', // MATHEMATICAL SCRIPT CAPITAL X
        0x1D4B4 => 'Y', // MATHEMATICAL SCRIPT CAPITAL Y
        0x1D4B5 => 'Z', // MATHEMATICAL SCRIPT CAPITAL Z
        // Script small a-z (U+1D4B6–U+1D4CF; some slots unassigned — in Letterlike)
        0x1D4B6 => 'a', // MATHEMATICAL SCRIPT SMALL A
        0x1D4B7 => 'b', // MATHEMATICAL SCRIPT SMALL B
        0x1D4B8 => 'c', // MATHEMATICAL SCRIPT SMALL C
        0x1D4B9 => 'd', // MATHEMATICAL SCRIPT SMALL D
        0x1D4BB => 'f', // MATHEMATICAL SCRIPT SMALL F
        0x1D4BD => 'h', // MATHEMATICAL SCRIPT SMALL H
        0x1D4BE => 'i', // MATHEMATICAL SCRIPT SMALL I
        0x1D4BF => 'j', // MATHEMATICAL SCRIPT SMALL J
        0x1D4C0 => 'k', // MATHEMATICAL SCRIPT SMALL K
        0x1D4C2 => 'm', // MATHEMATICAL SCRIPT SMALL M
        0x1D4C3 => 'n', // MATHEMATICAL SCRIPT SMALL N
        0x1D4C5 => 'p', // MATHEMATICAL SCRIPT SMALL P
        0x1D4C6 => 'q', // MATHEMATICAL SCRIPT SMALL Q
        0x1D4C7 => 'r', // MATHEMATICAL SCRIPT SMALL R
        0x1D4C8 => 's', // MATHEMATICAL SCRIPT SMALL S
        0x1D4C9 => 't', // MATHEMATICAL SCRIPT SMALL T
        0x1D4CA => 'u', // MATHEMATICAL SCRIPT SMALL U
        0x1D4CB => 'v', // MATHEMATICAL SCRIPT SMALL V
        0x1D4CC => 'w', // MATHEMATICAL SCRIPT SMALL W
        0x1D4CD => 'x', // MATHEMATICAL SCRIPT SMALL X
        0x1D4CE => 'y', // MATHEMATICAL SCRIPT SMALL Y
        0x1D4CF => 'z', // MATHEMATICAL SCRIPT SMALL Z
        // ── Bold Script (U+1D4D0–U+1D503) ────────────────────────────────────
        0x1D4D0..=0x1D4E9 => char::from_u32('A' as u32 + (cp - 0x1D4D0)).unwrap_or(c),
        0x1D4EA..=0x1D503 => char::from_u32('a' as u32 + (cp - 0x1D4EA)).unwrap_or(c),
        // ── Fraktur (U+1D504–U+1D537; some slots unassigned) ─────────────────
        0x1D504 => 'A',
        0x1D505 => 'B',
        0x1D507 => 'D',
        0x1D508 => 'E',
        0x1D509 => 'F',
        0x1D50A => 'G',
        0x1D50D => 'J',
        0x1D50E => 'K',
        0x1D50F => 'L',
        0x1D510 => 'M',
        0x1D511 => 'N',
        0x1D512 => 'O',
        0x1D513 => 'P',
        0x1D514 => 'Q',
        0x1D516 => 'S',
        0x1D517 => 'T',
        0x1D518 => 'U',
        0x1D519 => 'V',
        0x1D51A => 'W',
        0x1D51B => 'X',
        0x1D51C => 'Y',
        0x1D51E..=0x1D537 => char::from_u32('a' as u32 + (cp - 0x1D51E)).unwrap_or(c),
        // ── Double-Struck (U+1D538–U+1D56B; some slots unassigned) ───────────
        0x1D538 => 'A',
        0x1D539 => 'B',
        0x1D53B => 'D',
        0x1D53C => 'E',
        0x1D53D => 'F',
        0x1D53E => 'G',
        0x1D540 => 'I',
        0x1D541 => 'J',
        0x1D542 => 'K',
        0x1D543 => 'L',
        0x1D544 => 'M',
        0x1D546 => 'O',
        0x1D54A => 'S',
        0x1D54B => 'T',
        0x1D54C => 'U',
        0x1D54D => 'V',
        0x1D54E => 'W',
        0x1D54F => 'X',
        0x1D550 => 'Y',
        0x1D552..=0x1D56B => char::from_u32('a' as u32 + (cp - 0x1D552)).unwrap_or(c),
        // ── Bold Fraktur (U+1D56C–U+1D59F) ───────────────────────────────────
        0x1D56C..=0x1D585 => char::from_u32('A' as u32 + (cp - 0x1D56C)).unwrap_or(c),
        0x1D586..=0x1D59F => char::from_u32('a' as u32 + (cp - 0x1D586)).unwrap_or(c),
        // ── Sans-Serif (U+1D5A0–U+1D5D3) ─────────────────────────────────────
        0x1D5A0..=0x1D5B9 => char::from_u32('A' as u32 + (cp - 0x1D5A0)).unwrap_or(c),
        0x1D5BA..=0x1D5D3 => char::from_u32('a' as u32 + (cp - 0x1D5BA)).unwrap_or(c),
        // ── Sans-Serif Bold (U+1D5D4–U+1D607) ───────────────────────────────
        0x1D5D4..=0x1D5ED => char::from_u32('A' as u32 + (cp - 0x1D5D4)).unwrap_or(c),
        0x1D5EE..=0x1D607 => char::from_u32('a' as u32 + (cp - 0x1D5EE)).unwrap_or(c),
        // ── Sans-Serif Italic (U+1D608–U+1D63B) ──────────────────────────────
        0x1D608..=0x1D621 => char::from_u32('A' as u32 + (cp - 0x1D608)).unwrap_or(c),
        0x1D622..=0x1D63B => char::from_u32('a' as u32 + (cp - 0x1D622)).unwrap_or(c),
        // ── Sans-Serif Bold Italic (U+1D63C–U+1D66F) ─────────────────────────
        0x1D63C..=0x1D655 => char::from_u32('A' as u32 + (cp - 0x1D63C)).unwrap_or(c),
        0x1D656..=0x1D66F => char::from_u32('a' as u32 + (cp - 0x1D656)).unwrap_or(c),
        // ── Monospace (U+1D670–U+1D6A3) ──────────────────────────────────────
        0x1D670..=0x1D689 => char::from_u32('A' as u32 + (cp - 0x1D670)).unwrap_or(c),
        0x1D68A..=0x1D6A3 => char::from_u32('a' as u32 + (cp - 0x1D68A)).unwrap_or(c),
        _ => c,
    }
}

// ─── Channel Results ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ChannelDecision {
    Pass { intent: MatchedIntent },
    Block { reason: BlockReason },
    Fault { code: FaultCode },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelResult {
    pub channel: ChannelId,
    pub decision: ChannelDecision,
    pub elapsed_us: u64,
    /// Optional similarity score (primarily for Channel D).
    pub similarity: Option<f32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelId {
    A,
    B,
    C,
    D,
    E,
    F,
}

// ─── Intent / Block / Fault taxonomy ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MatchedIntent {
    QuestionFactual,
    QuestionCausal,
    QuestionComparative,
    TaskCodeGeneration,
    TaskTextSummarisation,
    TaskTranslation,
    TaskDataExtraction,
    ConversationalGreeting,
    ConversationalAcknowledgement,
    SystemMetaQuery,
    /// IP-050: Structured output request — JSON/XML/CSV schema output.
    /// Extra payload guards applied post-match (SA-018).
    StructuredOutput,
    /// IP-060: Agentic tool use — function/tool execution.
    AgenticToolUse,
    /// IP-099: Controlled creative — story/narrative/roleplay within strict bounds.
    /// Extra payload guards applied post-match (SA-018).
    /// NOTE: "roleplay as" is still blocked by RE-003/FP-003 — IP-099 only
    /// matches bounded creative framing ("write a story about", "write a poem about").
    ControlledCreative,
    /// Semantic violation: detected via embedding similarity (Channel D).
    SemanticViolation {
        similarity: f32,
        category: std::borrow::Cow<'static, str>,
    },
}

/// Structured reason for a Block decision.
/// pattern_id uses String (not &'static str) to allow Deserialize.
///
/// Note: `WatchdogTimeout` is defined here for API completeness and forward
/// compatibility, but is currently never produced by the runtime. The watchdog
/// fires `ChannelDecision::Fault { code: FaultCode::WatchdogFired }`, not a
/// Block. This variant is reserved for future use (e.g. a top-level timeout
/// wrapper outside the channel boundary). (G-17)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BlockReason {
    NoIntentMatch,
    ForbiddenPattern {
        pattern_id: String,
    },
    ExceededMaxLength,
    /// Reserved — not currently produced. See note above.
    WatchdogTimeout,
    MalformedInput {
        detail: String,
    },
    ProhibitedIntent {
        intent: MatchedIntent,
    },
    /// The input was flagged by semantic analysis (Channel D).
    SemanticTrigger {
        similarity: f32,
        reason: std::borrow::Cow<'static, str>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultCode {
    WatchdogFired,
    InternalPanic,
    RegexCompilationFailure,
}

// ─── Multi-message input ──────────────────────────────────────────────────────

/// A single message in a conversation, with an optional role tag.
/// Used as input to `evaluate_messages()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Role of the message author, e.g. "user", "assistant", "system".
    /// Informational only — not used in safety evaluation.
    pub role: String,
    /// Raw (unnormalised) message content. `evaluate_messages()` normalises
    /// each message via `PromptInput::new()` before evaluation.
    pub content: String,
}

/// Result of evaluating a multi-message conversation.
///
/// Fail-fast: evaluation stops at the first blocking message.
/// All messages up to and including the first block are included in `verdicts`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationVerdict {
    /// True if every message passed (no block in the conversation).
    pub is_pass: bool,
    /// Index of the first blocking message, if any.
    pub first_block_index: Option<usize>,
    /// Per-message verdicts. Contains all messages if `is_pass`, or messages
    /// up to and including the first block if `!is_pass`.
    pub verdicts: Vec<Verdict>,
}

impl ConversationVerdict {
    /// Returns the blocking `Verdict` if the conversation was blocked.
    pub fn blocking_verdict(&self) -> Option<&Verdict> {
        self.first_block_index.map(|i| &self.verdicts[i])
    }
}

// ─── Voter Output ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictKind {
    Pass,
    Block,
    DiagnosticAgreement,
    DiagnosticDisagreement,
    /// SA-069: Egress filtering blocked the LLM response.
    EgressBlock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub kind: VerdictKind,
    pub channel_a: ChannelResult,
    pub channel_b: ChannelResult,
    pub channel_d: Option<ChannelResult>,
    pub audit: AuditEntry,
}

impl Verdict {
    pub fn is_pass(&self) -> bool {
        matches!(
            self.kind,
            VerdictKind::Pass | VerdictKind::DiagnosticAgreement
        )
    }
}

// ─── Audit ────────────────────────────────────────────────────────────────────

/// Whether Channel C (advisory) agreed or disagreed with the 1oo2D voter.
/// Serialised as a simple tag so the audit log stays schema-stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdvisoryTag {
    /// Channel C and voter agree — no action needed.
    None,
    /// Channel C flagged suspicious but voter passed — review within 72h (SR-008).
    Disagreement { score: u8, heuristic_version: u16 },
    /// Channel C faulted — no safety impact, maintenance note.
    Fault,
}

/// SA-XXX: Configuration for audit entry detail level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditDetailLevel {
    /// Basic: Only store block_reason and hash (default, minimal storage).
    Basic,
    /// Detailed: Store full ChannelResult for operator review.
    /// Increases audit log size but enables side-by-side analysis.
    Detailed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Schema version — bump when adding/removing fields to enable migration detection.
    /// Consumers MUST check this field before deserialising. Current version: 2.
    ///
    /// Changelog:
    /// - v1: Initial schema
    /// - v2: Added channel_a_result, channel_b_result, audit_detail_level fields
    pub schema_version: u16,
    pub sequence: u64,
    pub ingested_at_ns: u128,
    pub decided_at_ns: u128,
    pub total_elapsed_us: u64,
    pub verdict_kind: VerdictKind,
    pub input_hash: String,
    /// Structured block reason for incident response.
    /// `Some` when verdict_kind is Block or DiagnosticDisagreement (blocking channel),
    /// `None` for Pass or DiagnosticAgreement (both channels passed).
    ///
    /// Source of the block reason:
    ///   - Both Block: Channel A reason used.
    ///   - Only B blocks (DiagnosticDisagreement, A=Pass): Channel B reason used.
    ///   - Only A blocks (DiagnosticDisagreement, B=Pass): Channel A reason used.
    ///   - DiagnosticAgreement (both Pass, intent mismatch): None — no block occurred.
    pub block_reason: Option<BlockReason>,
    /// SA-008: Advisory channel (Channel C) diagnostic tag.
    /// Never affects verdict — present for DC improvement only.
    /// Note: not currently exposed in JsVerdict (napi layer) — JS consumers
    /// must use the audit log for advisory events. (G-22)
    pub advisory: AdvisoryTag,
    /// SA-050: Channel D (Semantic) similarity score.
    pub semantic_similarity: Option<f32>,
    /// Audit Integrity: HMAC-chaining to prevent retrospective tampering.
    /// Chained to the `chain_hmac` of the previous entry.
    pub chain_hmac: Option<String>,
    /// SA-069: Egress validation result.
    pub egress_verdict: Option<VerdictKind>,
    pub egress_reason: Option<EgressBlockReason>,
    /// SA-XXX (v2): Channel A (FSM) full result for operator review.
    /// Only populated when audit_detail_level = Detailed.
    /// Enables side-by-side comparison with Channel B for DiagnosticDisagreement analysis.
    pub channel_a_result: Option<ChannelResult>,
    /// SA-XXX (v2): Channel B (Rule Engine) full result for operator review.
    /// Only populated when audit_detail_level = Detailed.
    /// Enables side-by-side comparison with Channel A for DiagnosticDisagreement analysis.
    pub channel_b_result: Option<ChannelResult>,
    /// SA-XXX (v2): Detail level for this audit entry.
    /// Determines whether channel results are populated.
    pub audit_detail_level: AuditDetailLevel,
}

impl AuditEntry {
    /// Create a Basic audit entry (v2 schema, minimal storage).
    pub fn basic(
        sequence: u64,
        verdict_kind: VerdictKind,
        block_reason: Option<BlockReason>,
        input_hash: String,
        advisory: AdvisoryTag,
        semantic_similarity: Option<f32>,
        chain_hmac: Option<String>,
        egress_verdict: Option<VerdictKind>,
        egress_reason: Option<EgressBlockReason>,
        ingested_at_ns: u128,
        decided_at_ns: u128,
        total_elapsed_us: u64,
    ) -> Self {
        Self {
            schema_version: 2,
            sequence,
            ingested_at_ns,
            decided_at_ns,
            total_elapsed_us,
            verdict_kind,
            input_hash,
            block_reason,
            advisory,
            semantic_similarity,
            chain_hmac,
            egress_verdict,
            egress_reason,
            channel_a_result: None,
            channel_b_result: None,
            audit_detail_level: AuditDetailLevel::Basic,
        }
    }

    /// Create a Detailed audit entry (v2 schema, includes channel results).
    pub fn detailed(
        sequence: u64,
        verdict_kind: VerdictKind,
        block_reason: Option<BlockReason>,
        input_hash: String,
        advisory: AdvisoryTag,
        semantic_similarity: Option<f32>,
        chain_hmac: Option<String>,
        egress_verdict: Option<VerdictKind>,
        egress_reason: Option<EgressBlockReason>,
        ingested_at_ns: u128,
        decided_at_ns: u128,
        total_elapsed_us: u64,
        channel_a_result: ChannelResult,
        channel_b_result: ChannelResult,
    ) -> Self {
        Self {
            schema_version: 2,
            sequence,
            ingested_at_ns,
            decided_at_ns,
            total_elapsed_us,
            verdict_kind,
            input_hash,
            block_reason,
            advisory,
            semantic_similarity,
            chain_hmac,
            egress_verdict,
            egress_reason,
            channel_a_result: Some(channel_a_result),
            channel_b_result: Some(channel_b_result),
            audit_detail_level: AuditDetailLevel::Detailed,
        }
    }

    /// Check if this entry has detailed channel results.
    pub fn has_channel_results(&self) -> bool {
        self.channel_a_result.is_some() && self.channel_b_result.is_some()
    }
}

/// SA-069: Egress blocking reason.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EgressBlockReason {
    SystemPromptLeakage { detail: String },
    PiiDetected { pii_type: String },
    HarmfulContent { category: String },
    Other { detail: String },
}

impl std::fmt::Display for EgressBlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SystemPromptLeakage { detail } => write!(f, "System Prompt Leakage: {}", detail),
            Self::PiiDetected { pii_type } => write!(f, "PII Detected: {}", pii_type),
            Self::HarmfulContent { category } => write!(f, "Harmful Content: {}", category),
            Self::Other { detail } => write!(f, "Egress Block: {}", detail),
        }
    }
}

/// SA-069: Result of an egress evaluation via `evaluate_output()`.
/// Carries the verdict, structured block reason, and a full audit entry
/// with HMAC chaining so egress decisions are traceable in the audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressVerdict {
    /// Convenience alias — same as `egress_verdict`.
    pub kind: VerdictKind,
    pub egress_verdict: VerdictKind,
    pub egress_reason: Option<EgressBlockReason>,
    /// Full audit entry for this egress evaluation (with chain_hmac populated).
    /// `None` only if the firewall was not initialised.
    pub audit: Option<AuditEntry>,
}

impl EgressVerdict {
    pub fn is_pass(&self) -> bool {
        matches!(self.kind, VerdictKind::Pass)
    }
}

// ─── Review Tracking (SA-072) ──────────────────────────────────────────────────

/// Status of a diagnostic review item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewStatus {
    Pending,
    Reviewed {
        reviewed_at_ns: u128,
        reviewer: String,
    },
    Expired,
}

/// A diagnostic item that requires operator review.
/// Created when DiagnosticDisagreement or DiagnosticAgreement events occur.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewItem {
    pub sequence: u64,
    pub created_at_ns: u128,
    pub review_by_ns: u128,
    pub status: ReviewStatus,
    pub verdict_kind: VerdictKind,
    pub input_hash: String,
    pub advisory_score: Option<u8>,
}

impl ReviewItem {
    pub fn new(
        sequence: u64,
        verdict_kind: VerdictKind,
        input_hash: String,
        advisory_score: Option<u8>,
        sla_hours: u32,
    ) -> Self {
        use std::time::{Duration, SystemTime, UNIX_EPOCH};
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos();
        let sla_ns = (sla_hours as u128) * 3_600_000_000_000_u128;
        Self {
            sequence,
            created_at_ns: now_ns,
            review_by_ns: now_ns + sla_ns,
            status: ReviewStatus::Pending,
            verdict_kind,
            input_hash,
            advisory_score,
        }
    }

    pub fn is_expired(&self) -> bool {
        use std::time::{Duration, SystemTime, UNIX_EPOCH};
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos();
        self.status == ReviewStatus::Pending && now_ns > self.review_by_ns
    }
}
