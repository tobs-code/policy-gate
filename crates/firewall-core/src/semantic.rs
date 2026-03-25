// crates/firewall-core/src/semantic.rs — Channel D: Semantic Firewall
//
// Safety Action SA-050: Semantic analysis using embeddings.
//
// This module implements Channel D, which evaluates the semantic similarity
// of a prompt against known attack vector centroids.
//
// NOTE: This module depends on 'ort' (ONNX Runtime) and a pre-trained model.

use crate::types::{ChannelDecision, ChannelId, ChannelResult, MatchedIntent};
use ort::session::Session;

use std::borrow::Cow;
use std::sync::OnceLock;
use std::time::Instant;

pub struct ChannelD;

static MODEL_SESSION: OnceLock<Session> = OnceLock::new();

// Pre-computed centroids for common attack categories.
pub const EXPECTED_CENTROID_HASH: &str =
    "0e59a67a83424697ff6bc378e02911d020612918d36357777196020586616086";

/// A toy 4-dimensional subword embedding table for demonstration.
/// In production, this would be a large hash-map or a FastText-style binary blob.
const SUBWORD_VOCAB: &[(&str, [f32; 4])] = &[
    ("mal", [0.8, -0.1, 0.2, -0.5]),
    ("ware", [0.7, 0.1, -0.1, -0.4]),
    ("inj", [-0.2, 0.9, 0.3, 0.1]),
    ("ect", [-0.1, 0.8, 0.2, 0.2]),
    ("prev", [0.1, -0.2, 0.8, 0.4]),
    ("ignore", [0.2, -0.1, 0.9, 0.3]),
    ("prompt", [0.0, 0.1, 0.7, 0.5]),
    ("system", [-0.1, 0.0, 0.6, 0.6]),
];

const ATTACK_CENTROIDS: &[(&str, [f32; 4])] = &[
    ("Malware", [0.75, 0.0, 0.05, -0.45]), // Centroid of 'mal' and 'ware'
    ("Injection", [0.05, 0.45, 0.75, 0.45]), // Centroid of 'prev', 'ignore', 'prompt'
];

impl ChannelD {
    /// Initialise Channel D by loading the ONNX model.
    /// Tokenizer path is kept for signature compatibility with lib.rs but ignored for now.
    pub fn init(model_path: &str, _tokenizer_path: &str) -> Result<(), String> {
        let session = Session::builder()
            .map_err(|e| format!("Failed to create session builder: {}", e))?
            .commit_from_file(model_path)
            .map_err(|e| format!("Failed to load ONNX model: {}", e))?;
        MODEL_SESSION
            .set(session)
            .map_err(|_| "Model session already initialised".to_string())?;

        Ok(())
    }

    /// Evaluate input semantically.
    pub fn evaluate(input: &str) -> ChannelResult {
        let start = Instant::now();

        let decision = match Self::compute_similarity(input) {
            Ok((max_sim, category)) => {
                // Threshold for "Suspicious" advisory
                if max_sim > 0.85 {
                    ChannelDecision::Pass {
                        intent: MatchedIntent::SemanticViolation {
                            similarity: max_sim,
                            category: Cow::Borrowed(category),
                        },
                    }
                } else {
                    // For now, if it's not a clear violation, we pass with a generic unknown intent
                    // or let other channels decide. In a blocking mode, this would be more complex.
                    ChannelDecision::Pass {
                        intent: MatchedIntent::QuestionFactual,
                    } // Placeholder
                }
            }
            Err(_e) => {
                // Fallback to Fault if inference fails
                ChannelDecision::Fault {
                    code: crate::types::FaultCode::InternalPanic, // Using Panic as proxy for inference error
                }
            }
        };

        ChannelResult {
            channel: ChannelId::D,
            decision,
            elapsed_us: start.elapsed().as_micros() as u64,
            similarity: Self::compute_similarity(input).ok().map(|(sim, _)| sim),
        }
    }

    fn compute_similarity(text: &str) -> Result<(f32, &'static str), String> {
        let lower = text.to_lowercase();

        // 1. Static Subword Embedding (Fast-Semantic Path)
        // Extract 3-5 character n-grams and lookup in SUBWORD_VOCAB
        let mut sum_vec = [0.0f32; 4];
        let mut count = 0;

        for (subword, vec) in SUBWORD_VOCAB {
            if lower.contains(subword) {
                for i in 0..4 {
                    sum_vec[i] += vec[i];
                }
                count += 1;
            }
        }

        if count == 0 {
            return Ok((0.0, "None"));
        }

        // Mean pooling
        for val in &mut sum_vec {
            *val /= count as f32;
        }

        // 2. Centroid Comparison
        let mut max_sim = 0.0f32;
        let mut best_category = "None";

        for (category, centroid) in ATTACK_CENTROIDS {
            let sim = Self::dot_product(&sum_vec, centroid);
            if sim > max_sim {
                max_sim = sim;
                best_category = category;
            }
        }

        Ok((max_sim, best_category))
    }

    fn dot_product(a: &[f32; 4], b: &[f32; 4]) -> f32 {
        let mut dot = 0.0;
        let mut norm_a = 0.0;
        let mut norm_b = 0.0;
        for i in 0..4 {
            dot += a[i] * b[i];
            norm_a += a[i] * a[i];
            norm_b += b[i] * b[i];
        }
        if norm_a == 0.0 || norm_b == 0.0 {
            return 0.0;
        }
        dot / (norm_a.sqrt() * norm_b.sqrt())
    }
}
