// advisory.rs — Channel C: Advisory (non-safety) third channel
//
// Safety Action SA-008: Triplex voter with ML advisory channel.
//
// Architecture boundary:
//   This module is OUTSIDE the safety-critical boundary.
//   Its output NEVER gates the Pass/Block decision — that is solely
//   determined by the 1oo2D voter (Channels A + B).
//
//   Channel C's sole purpose is to raise DiagnosticEvents when it
//   disagrees with the 1oo2D voter outcome, increasing Diagnostic
//   Coverage toward DC_high (≥ 99%).
//
// Design constraints:
//   • Channel C MUST NOT be in the safety function call chain.
//   • A Channel C fault MUST NOT affect the voter output.
//   • Channel C uses heuristic/lexical scoring — diverse from A and B.
//   • No regex (diverse from A), no ML model dependency at compile time.
//
// Diagnostic event raised when:
//   • Voter says Pass, Channel C says Suspicious  → AdvisoryDisagreement
//   • Voter says Block, Channel C says Safe       → AdvisoryAgreement (no event)
//   • Channel C faults                            → AdvisoryFault (logged, ignored)
//
// DC-GAP-02: Heuristic version is tracked via HEURISTIC_VERSION and included
// in every AdvisoryDisagreement event. When new jailbreak classes are identified,
// bump HEURISTIC_VERSION and add corresponding heuristics. Audit logs then show
// which version produced each verdict, enabling retrospective coverage analysis.

use crate::types::VerdictKind;

/// Monotonic version of the Channel C heuristic set.
/// Bump this when adding, removing, or materially changing any heuristic (H-C01…).
/// The version is included in AdvisoryDisagreement events so audit logs can be
/// correlated with the heuristic set that was active at evaluation time.
pub const HEURISTIC_VERSION: u16 = 2;

// ─── Types ────────────────────────────────────────────────────────────────────

/// Channel C opinion — purely advisory, never gates the verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvisoryOpinion {
    /// Input appears safe based on heuristic scoring.
    Safe,
    /// Input has suspicious characteristics — operator should review.
    Suspicious { score: u8, reason: &'static str },
    /// Channel C encountered an internal error — ignored by voter.
    Fault { detail: &'static str },
}

/// Diagnostic event emitted when Channel C disagrees with the 1oo2D voter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvisoryEvent {
    /// Voter passed, Channel C flagged suspicious — review recommended.
    /// Does NOT change the verdict. Operator must review within 72h (SR-008).
    AdvisoryDisagreement {
        score: u8,
        reason: &'static str,
        heuristic_version: u16,
    },
    /// Channel C faulted — logged for maintenance, no safety impact.
    AdvisoryFault { detail: &'static str },
    /// No disagreement — Channel C and voter agree.
    None,
}

// ─── Channel C implementation ─────────────────────────────────────────────────

pub struct ChannelC;

impl ChannelC {
    /// Evaluate input heuristically. Pure lexical scoring — no regex, no ML.
    /// Returns an AdvisoryOpinion. This function MUST NOT panic.
    pub fn evaluate(input: &str) -> AdvisoryOpinion {
        // Guard: empty input is trivially safe (voter will block it anyway)
        if input.is_empty() {
            return AdvisoryOpinion::Safe;
        }

        // Score accumulates suspicion points. Threshold = 3 → Suspicious.
        let mut score: u8 = 0;
        let lower = input.to_lowercase();
        let char_count = input.chars().count();

        // Heuristic H-C01: unusual punctuation density
        // High ratio of special chars relative to total char count is suspicious.
        // Threshold: >10% special chars (1 in 10).
        let special_count = input
            .chars()
            .filter(|c| {
                matches!(
                    *c,
                    '<' | '>' | '|' | '{' | '}' | '[' | ']' | '\\' | '^' | '`'
                )
            })
            .count();
        if char_count > 0 && special_count * 10 > char_count {
            score = score.saturating_add(3); // alone sufficient to trigger
        }

        // Heuristic H-C02: instruction-like imperative verbs at sentence start
        // These are common in jailbreak prompts even when injection markers are absent.
        const IMPERATIVE_STARTS: &[&str] = &[
            "now ",
            "instead ",
            "actually ",
            "wait ",
            "stop ",
            "override ",
            "bypass ",
            "unlock ",
            "enable ",
            "disable ",
            "reveal ",
            "expose ",
            "print ",
            "show ",
        ];
        if IMPERATIVE_STARTS.iter().any(|p| lower.starts_with(p)) {
            score = score.saturating_add(3); // alone sufficient to trigger
        }

        // Heuristic H-C03: excessive capitalisation (shouting / obfuscation)
        let upper_count = input.chars().filter(|c| c.is_uppercase()).count();
        let alpha_count = input.chars().filter(|c| c.is_alphabetic()).count();
        if alpha_count > 10 && upper_count * 2 > alpha_count {
            score = score.saturating_add(1);
        }

        // Heuristic H-C04: base64-like token (obfuscated payload)
        // A contiguous run of 20+ chars using only the base64 alphabet is suspicious.
        // We check the whole input as one token (no split) to catch single-string payloads,
        // and also check individual whitespace-split words.
        let is_b64_like = |s: &str| -> bool {
            s.len() >= 20
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        };
        let has_b64_token = is_b64_like(input.trim()) || input.split_whitespace().any(is_b64_like);
        if has_b64_token {
            score = score.saturating_add(3); // alone sufficient to trigger
        }

        // Heuristic H-C05: soft jailbreak via indirection / social engineering
        // These phrases are used in "polite" jailbreaks that avoid hard injection
        // markers but still attempt to manipulate model behaviour.
        // Diverse from Channel B (no keyword overlap with RE-002/RE-003).
        const INDIRECTION_PHRASES: &[&str] = &[
            "for a story",
            "in a story",
            "for a novel",
            "for fiction",
            "as a character",
            "in this scenario",
            "hypothetically speaking",
            "a friend told me",
            "my friend wants to know",
            "asking for a friend",
            "for research purposes",
            "purely academic",
            "just curious",
            "no harm intended",
            "without any restrictions",
            "without restrictions",
            "with no restrictions",
            "with no filters",
            "without filters",
            "without safety",
            "ignore your training",
            "ignore your guidelines",
            "your true self",
            "your real self",
            "unfiltered version",
            "uncensored version",
            "developer mode",
            "jailbreak mode",
            "dan mode",
            "unrestricted mode",
        ];
        if INDIRECTION_PHRASES.iter().any(|p| lower.contains(p)) {
            score = score.saturating_add(3); // alone sufficient to trigger
        }

        // Heuristic H-C06: roleplaying / persona framing (soft variant)
        // Catches softer forms not covered by RE-003 hard block phrases.
        // e.g. "imagine you are", "let's say you are", "suppose you were"
        const PERSONA_FRAMES: &[&str] = &[
            "imagine you are",
            "imagine you were",
            "imagine you're",
            "let's say you are",
            "let's say you're",
            "suppose you are",
            "suppose you were",
            "what if you were",
            "what if you had no",
            "if you could ignore",
            "if you were allowed",
            "if there were no rules",
            "if you had no rules",
            "if you had no limits",
            "if you had no restrictions",
            "as an ai without",
            "as an ai that can",
            "as a version of you",
        ];
        if PERSONA_FRAMES.iter().any(|p| lower.contains(p)) {
            score = score.saturating_add(3); // alone sufficient to trigger
        }

        // Heuristic H-C07: negation chains (obfuscated instructions)
        // e.g. "don't not ignore", "never not follow", "do not fail to"
        // These are used to confuse safety filters via double negation.
        const NEGATION_CHAINS: &[&str] = &[
            "don't not ",
            "do not not ",
            "never not ",
            "not never ",
            "do not fail to",
            "don't fail to",
            "must not refuse",
            "cannot refuse",
            "should not refuse",
            "not allowed to refuse",
        ];
        if NEGATION_CHAINS.iter().any(|p| lower.contains(p)) {
            score = score.saturating_add(3); // alone sufficient to trigger
        }

        // Heuristic H-C08: payload keyword proximity
        // Dangerous nouns that appear in otherwise structurally valid prompts
        // (e.g. "Write a function that exfiltrates passwords").
        // Adds 1 point per hit — combined with other signals reaches threshold.
        // Note: H-C08 uses broader bare keywords (e.g. "sql injection", "brute force")
        // intentionally — advisory scoring benefits from sensitivity over precision.
        // FP-003/RE-004 use narrower offensive-framing variants to avoid FPs in
        // defensive code contexts. H-C08 is non-blocking so broader coverage is safe.
        // Last sync review: SA-036.
        const PAYLOAD_NOUNS: &[&str] = &[
            // Malware categories
            "malware",
            "ransomware",
            "keylogger",
            "rootkit",
            "backdoor",
            "shellcode",
            "exfiltrate",
            "exfiltration",
            "reverse shell",
            "bind shell",
            "privilege escalation",
            "privesc",
            "lateral movement",
            "command and control",
            "c2 server",
            // Exploit techniques
            "exploit",
            "payload",
            "sql injection",
            "sqli",
            "xss payload",
            "cross-site scripting",
            "buffer overflow",
            "heap spray",
            "use-after-free",
            "path traversal",
            "directory traversal",
            "remote code execution",
            "arbitrary code execution",
            "deserialization exploit",
            "xml external entity",
            "xxe",
            "server-side request forgery",
            "ssrf",
            "ldap injection",
            "nosql injection",
            "os command injection",
            "template injection",
            "ssti",
            "prototype pollution",
            "http request smuggling",
            "arp poison",
            "dns spoof",
            "man-in-the-middle",
            "mitm",
            "brute force",
            "credential stuffing",
            "wpa crack",
            "wifi crack",
            "memory dump",
            "dump memory",
            "av evasion",
            "antivirus evasion",
            "polymorphic",
            // Auth bypass
            "bypass authentication",
            "bypass auth",
            "bypass 2fa",
            "bypass mfa",
            "bypass firewall",
            "bypass filter",
            // Credentials / sensitive targets
            "credential",
            "credentials",
            "passwd",
            "shadow file",
            "/etc/passwd",
            "/etc/shadow",
            "id_rsa",
            "aws_secret",
            "private key",
            "api key",
            // Social harm
            "deepfake porn",
            "stalkerware",
            "dox",
            "doxx",
            "money laundering",
            "launder money",
            "synthesize meth",
            "make a bomb",
            "synthesize ricin",
            // Attack verbs
            "hack into",
            "hacks into",
            "steal",
            "steals",
            "hijack",
            "hijacks",
            "phishing",
            "ddos",
            "denial of service",
            "cyberattack",
            "unauthorized access",
            "stalk and harass",
            // Multilingual attack keywords (DE, FR, ES) - Gap 3 sync
            "schadcode",
            "trojaner",
            "angriff",
            "piraterie",
            "schadhaft",
            "malicieux",
            "pirater",
            "malveillant",
            "supprimer",
            "piratear",
            "borrar",
            "ataque",
            "robba",
        ];
        let payload_hits = PAYLOAD_NOUNS.iter().filter(|p| lower.contains(*p)).count();
        score = score.saturating_add(payload_hits.min(3) as u8);

        if score >= 3 {
            AdvisoryOpinion::Suspicious {
                score,
                reason: "heuristic suspicion score threshold exceeded",
            }
        } else {
            AdvisoryOpinion::Safe
        }
    }

    /// Compare Channel C opinion against the 1oo2D voter verdict.
    /// Returns an AdvisoryEvent for the audit trail.
    /// This function MUST NOT affect the verdict.
    pub fn audit_event(opinion: &AdvisoryOpinion, verdict: &VerdictKind) -> AdvisoryEvent {
        match opinion {
            AdvisoryOpinion::Fault { detail } => AdvisoryEvent::AdvisoryFault { detail },

            AdvisoryOpinion::Suspicious { score, reason } => {
                // Only raise an event if the voter passed — disagreement case.
                match verdict {
                    VerdictKind::Pass | VerdictKind::DiagnosticAgreement => {
                        AdvisoryEvent::AdvisoryDisagreement {
                            score: *score,
                            reason,
                            heuristic_version: HEURISTIC_VERSION,
                        }
                    }
                    VerdictKind::Block
                    | VerdictKind::DiagnosticDisagreement
                    | VerdictKind::EgressBlock => {
                        // Voter already blocked — Channel C agrees on outcome.
                        AdvisoryEvent::None
                    }
                }
            }

            AdvisoryOpinion::Safe => AdvisoryEvent::None,
        }
    }
}
