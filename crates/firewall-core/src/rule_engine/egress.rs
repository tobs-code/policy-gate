// rule_engine/egress.rs — Channel F: Rule-based Egress for output validation
//
// Specialized in:
// 1. Obfuscated Leakage Detection (High entropy / Base64 / Hex patterns)
// 2. Prohibited Framing (Detecting "As an AI model...", "Here is the secret key:")

use crate::types::{ChannelDecision, ChannelId, ChannelResult, PromptInput};

pub struct ChannelF;

impl ChannelF {
    pub fn evaluate(_prompt: &PromptInput, response: &str) -> ChannelResult {
        let start = std::time::Instant::now();

        // 1. Obfuscated Leakage: Look for Base64/Hex buffers that might leak secrets
        if let Some(obfuscated) = detect_obfuscated_data(response) {
            return ChannelResult {
                channel: ChannelId::F,
                decision: ChannelDecision::Block {
                    reason: crate::types::BlockReason::MalformedInput {
                        detail: format!("Obfuscated/Encoded data detected: {}", obfuscated),
                    },
                },
                elapsed_us: start.elapsed().as_micros() as u64,
                similarity: None,
            };
        }

        // 2. Prohibited Framing: Rejection of stereotypical leak patterns
        let framing_patterns = [
            "the system prompt",
            "the hidden instructions",
            "here is the secret key",
            "secret_key =",
            "private_key =",
        ];

        let lower_response = response.to_lowercase();
        for pattern in framing_patterns {
            if lower_response.contains(pattern) {
                return ChannelResult {
                    channel: ChannelId::F,
                    decision: ChannelDecision::Block {
                        reason: crate::types::BlockReason::ForbiddenPattern {
                            pattern_id: format!(
                                "EGRESS-RE-001-{}",
                                pattern.replace(' ', "-").to_uppercase()
                            ),
                        },
                    },
                    elapsed_us: start.elapsed().as_micros() as u64,
                    similarity: None,
                };
            }
        }

        ChannelResult {
            channel: ChannelId::F,
            decision: ChannelDecision::Pass {
                intent: crate::types::MatchedIntent::ConversationalAcknowledgement,
            },
            elapsed_us: start.elapsed().as_micros() as u64,
            similarity: None,
        }
    }
}

fn detect_obfuscated_data(text: &str) -> Option<&'static str> {
    // Detect potential Base64 blobs (> 32 chars of Base64 set)
    let b64_count = text
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();
    if b64_count > 64 && text.len() > 64 {
        // High density check
        let density = b64_count as f32 / text.len() as f32;
        if density > 0.9 {
            return Some("Potential Base64/Encoded data");
        }
    }
    None
}
