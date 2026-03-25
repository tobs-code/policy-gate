// fsm/egress.rs — Channel E: Egress FSM for output validation
//
// Specialized in:
// 1. System Prompt Leakage (substring / partial overlap)
// 2. PII Detection (Regex-based patterns for SSN, Credit Cards)

use crate::types::{ChannelDecision, ChannelId, ChannelResult, PromptInput};
use regex::Regex;
use std::sync::OnceLock;

pub struct ChannelE;

impl ChannelE {
    pub fn evaluate(prompt: &PromptInput, response: &str) -> ChannelResult {
        let start = std::time::Instant::now();

        // 1. Check for System Prompt Leakage
        // SA-069: We look for significant chunks of the normalized prompt appearing in the response.
        // We use a case-insensitive sliding window check.
        if let Some(leak) = find_leakage(&prompt.text, response) {
            return ChannelResult {
                channel: ChannelId::E,
                decision: ChannelDecision::Block {
                    reason: crate::types::BlockReason::MalformedInput {
                        detail: format!("Potential system prompt leakage: {}", leak),
                    },
                },
                elapsed_us: start.elapsed().as_micros() as u64,
                similarity: None,
            };
        }

        // 2. check for PII
        if let Some(pii_type) = find_pii(response) {
            return ChannelResult {
                channel: ChannelId::E,
                decision: ChannelDecision::Block {
                    reason: crate::types::BlockReason::MalformedInput {
                        detail: format!("PII detected: {}", pii_type),
                    },
                },
                elapsed_us: start.elapsed().as_micros() as u64,
                similarity: None,
            };
        }

        ChannelResult {
            channel: ChannelId::E,
            decision: ChannelDecision::Pass {
                intent: crate::types::MatchedIntent::ConversationalAcknowledgement,
            },
            elapsed_us: start.elapsed().as_micros() as u64,
            similarity: None,
        }
    }
}

const WINDOW_SIZE: usize = 20;
/// Minimum prompt length before egress leakage check runs.
/// Set to 60 to avoid false positives for short factual prompts that are
/// naturally echoed in correct responses (e.g. "capital of France" → "Paris, the capital.").
const MIN_PROMPT_LEN: usize = 60;
const MIN_SIGNIFICANT_CHARS: usize = 10;

static PROGRAMMING_KEYWORDS: OnceLock<Vec<&'static str>> = OnceLock::new();

fn get_programming_keywords() -> &'static Vec<&'static str> {
    PROGRAMMING_KEYWORDS.get_or_init(|| {
        vec![
            "if",
            "else",
            "for",
            "while",
            "return",
            "const",
            "let",
            "var",
            "function",
            "class",
            "interface",
            "public",
            "private",
            "static",
            "void",
            "import",
            "export",
            "struct",
            "enum",
            "fn",
            "impl",
            "trait",
            "where",
            "select",
            "from",
            "insert",
            "update",
            "delete",
            "async",
            "await",
            "yield",
            "break",
            "continue",
            "match",
            "case",
            "default",
            "try",
            "catch",
            "finally",
            "throw",
            "new",
            "delete",
            "typeof",
            "instanceof",
            "package",
            "namespace",
            "using",
            "include",
            // Common boilerplate / low-entropy terms
            "main",
            "args",
            "argv",
            "argc",
            "string",
            "bool",
            "int",
            "float",
            "double",
            "char",
            "byte",
            "long",
            "short",
            "signed",
            "unsigned",
            "system",
            "console",
            "println",
            "print",
            "log",
            "debug",
            "error",
            "null",
            "true",
            "false",
            "self",
            "this",
            "super",
            "null",
            "undefined",
            "std",
            "cout",
            "cin",
            "endl",
        ]
    })
}

fn is_significant(chunk: &str) -> bool {
    // 1. Strip all non-alphanumeric characters first
    let alphanumeric_only: String = chunk
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();

    let keywords = get_programming_keywords();
    let mut cleaned = alphanumeric_only;

    // 2. Remove all common keywords from the chunk
    for kw in keywords {
        cleaned = cleaned.replace(kw, "");
    }

    // A chunk is significant if it has enough characters left that are NOT keywords
    // With a 20-char window, needing 10 "unique" chars is a strong signal for leakage.
    cleaned.len() >= MIN_SIGNIFICANT_CHARS
}

fn find_leakage(prompt: &str, response: &str) -> Option<String> {
    let lower_prompt = prompt.to_lowercase();

    let (normalised_response, _) = match crate::types::PromptInput::normalise_text(response) {
        Ok(res) => res,
        Err(_) => return None,
    };
    let lower_response = normalised_response.to_lowercase();

    if lower_prompt.len() < MIN_PROMPT_LEN || lower_response.len() < WINDOW_SIZE {
        return None;
    }

    for i in 0..=(lower_prompt.len() - WINDOW_SIZE) {
        let chunk = &lower_prompt[i..i + WINDOW_SIZE];
        if lower_response.contains(chunk) {
            // New Significance Check: Only block if the matched chunk is not just boilerplate code
            if is_significant(chunk) {
                return Some(chunk.to_string());
            }
        }
    }
    None
}

static PII_REGEXES: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();

fn find_pii(text: &str) -> Option<&'static str> {
    let regexes = PII_REGEXES.get_or_init(|| {
        vec![
            ("Phone (Intl)", Regex::new(r"\+\d{8,15}").unwrap()),
            ("Phone (US)", Regex::new(r"\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b").unwrap()),
            ("IPv4", Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b").unwrap()),
            ("IPv6", Regex::new(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b").unwrap()),
            ("IBAN", Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b").unwrap()),
            ("Credit Card", Regex::new(r"\b(?:\d{4}[- ]?){3}\d{1,4}\b").unwrap()),
            ("SSN", Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap()),
            ("Email", Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap()),
            ("GitHub Token", Regex::new(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b").unwrap()),
            ("AWS Key", Regex::new(r"\b(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b").unwrap()),
            ("API Key", Regex::new(r"(?i)\b(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key)\s*[:=]\s*['\x22]?[A-Za-z0-9_\-]{16,}").unwrap()),
            ("Bearer Token", Regex::new(r"(?i)\bbearer\s+[A-Za-z0-9_\-\.]{20,}").unwrap()),
            ("Password", Regex::new(r"(?i)\b(?:password|passwd|pwd|pass)\s*[:=]\s*['\x22]?[^\s'\x22]{4,}").unwrap()),
        ]
    });

    for (name, re) in regexes {
        if re.is_match(text) {
            return Some(name);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_significant() {
        // Boilerplate code should NOT be significant
        assert!(!is_significant("publicstaticvoidmain"));
        assert!(!is_significant("functionfallback()"));

        // Actual secret/unique content should be significant
        assert!(is_significant("secret_key_123456789"));
        assert!(is_significant("admin_password_prime"));
    }

    #[test]
    fn test_find_leakage_with_boilerplate() {
        // All-keyword prompt — every 20-char window will be stripped to zero significant chars.
        // Combined length > 60 to satisfy MIN_PROMPT_LEN.
        let p_text = "public static void main string return null false const let var";
        let prompt = crate::types::PromptInput::new(p_text).unwrap();
        let response =
            "Here is code: public static void main string return null false const let var";

        // Should NOT block because the overlap is just boilerplate keywords
        assert!(
            find_leakage(&prompt.text, response).is_none(),
            "Should allow boilerplate code"
        );

        // Actual secret leakage — prompt >= 60 normalized chars
        // Use space-separated tokens (underscores get stripped by normaliser)
        let s_text = "INTERNAL SECRET HIDDENACCESSTOKEN XYZ123 ALPHAPROTOCOL CLASSIFIED TOPLEVEL";
        let prompt_secret = crate::types::PromptInput::new(s_text).unwrap();
        let response_leak =
            "I can see: INTERNAL SECRET HIDDENACCESSTOKEN XYZ123 ALPHAPROTOCOL CLASSIFIED TOPLEVEL";

        // Should STILL block actual secret leakage
        assert!(
            find_leakage(&prompt_secret.text, response_leak).is_some(),
            "Should block real leakage"
        );
    }

    #[test]
    fn test_find_pii_extended() {
        // Original patterns
        assert_eq!(find_pii("Card: 4111-1111-1111-1111"), Some("Credit Card"));
        assert_eq!(find_pii("SSN: 123-45-6789"), Some("SSN"));
        assert_eq!(find_pii("Email: user@example.com"), Some("Email"));

        // New patterns
        assert_eq!(find_pii("Call me at (555) 123-4567"), Some("Phone (US)"));
        assert_eq!(find_pii("Contact: +1-555-123-4567"), Some("Phone (US)"));

        let intl_test = find_pii("International: +4915112345678");
        assert!(
            intl_test == Some("Phone (Intl)") || intl_test == Some("Phone (US)"),
            "Expected Phone match, got {:?}",
            intl_test
        );

        assert_eq!(find_pii("Server IP: 192.168.1.1"), Some("IPv4"));
        assert_eq!(
            find_pii("IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            Some("IPv6")
        );

        assert_eq!(find_pii("IBAN: DE89370400440532013000"), Some("IBAN"));
        assert_eq!(
            find_pii("EU IBAN: FR7630006000011234567890189"),
            Some("IBAN")
        );

        assert_eq!(find_pii("api_key = sk_live_abc123xyz7890"), Some("API Key"));
        assert_eq!(
            find_pii("API-KEY: my_secret_key_here12345"),
            Some("API Key")
        );
        assert_eq!(
            find_pii("apikey=bGVnYWN5c2VjcmV0MTIzNDU2Nzg5MA=="),
            Some("API Key")
        );

        assert_eq!(
            find_pii("AWS Access Key: AKIAIOSFODNN7EXAMPLE"),
            Some("AWS Key")
        );
        assert_eq!(find_pii("AKIAJ7LGHPZ6VBJCGQKA"), Some("AWS Key"));

        assert_eq!(find_pii("password: supersecret123"), Some("Password"));
        assert_eq!(find_pii("pwd='hunter2'"), Some("Password"));
        assert_eq!(find_pii("pass = letmein"), Some("Password"));

        assert_eq!(
            find_pii("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
            Some("Bearer Token")
        );

        assert_eq!(
            find_pii("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
            Some("GitHub Token")
        );

        // No PII
        assert!(find_pii("Hello world, this is a normal response").is_none());
        assert!(find_pii("API rate limit is 100 requests per minute").is_none());
    }
}
