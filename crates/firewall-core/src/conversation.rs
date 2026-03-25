use crate::init::get_config;
use crate::{evaluate_raw, ChatMessage, ConversationVerdict};

/// Evaluate a multi-message conversation through the safety gate.
///
/// Each message is normalised and evaluated independently via `evaluate_raw()`.
/// Evaluation is fail-fast: stops at the first blocking message.
///
/// `base_sequence` is the sequence number for the first message; subsequent
/// messages use `base_sequence + 1`, `base_sequence + 2`, etc.
/// Pass `next_sequence()` to get a process-wide monotonic counter.
///
/// Returns a `ConversationVerdict` with per-message verdicts and the index
/// of the first blocking message (if any).
///
/// This version uses a sliding window (default 3 or via `firewall.toml`)
/// to detect cross-message payload fragmentation (Red-Team Strategy 3).
pub fn evaluate_messages(messages: &[ChatMessage], base_sequence: u64) -> ConversationVerdict {
    let window = get_config().and_then(|c| c.context_window).unwrap_or(3);
    evaluate_messages_windowed(messages, window, base_sequence)
}

/// Evaluates a conversation with a configurable lookback window for contextual safety.
///
/// For each message `i`, this performs:
/// 1. Individual safety check of message `i`.
/// 2. Contextual check of the last `window_size` messages (joined with spaces).
///
/// The contextual check detects "Payload Fragmentation" where malicious content
/// is spread across multiple turns.
pub fn evaluate_messages_windowed(
    messages: &[ChatMessage],
    window_size: usize,
    base_sequence: u64,
) -> ConversationVerdict {
    let mut verdicts = Vec::with_capacity(messages.len());

    for (i, msg) in messages.iter().enumerate() {
        let v = evaluate_raw(msg.content.clone(), base_sequence + i as u64);
        if !v.is_pass() {
            verdicts.push(v);
            return ConversationVerdict {
                is_pass: false,
                first_block_index: Some(i),
                verdicts,
            };
        }

        if window_size > 1 && i > 0 {
            let start = i.saturating_sub(window_size - 1);
            let context_slice = &messages[start..=i];

            let mut combined = String::new();
            for (cj, cm) in context_slice.iter().enumerate() {
                if cj > 0 {
                    combined.push(' ');
                }
                combined.push_str(&cm.content);
                if combined.len() > 8192 {
                    break;
                }
            }

            let cv = evaluate_raw(combined, base_sequence + i as u64 + 100_000);
            if !cv.is_pass() {
                verdicts.push(cv);
                return ConversationVerdict {
                    is_pass: false,
                    first_block_index: Some(i),
                    verdicts,
                };
            }
        }

        verdicts.push(v);
    }

    ConversationVerdict {
        is_pass: true,
        first_block_index: None,
        verdicts,
    }
}
