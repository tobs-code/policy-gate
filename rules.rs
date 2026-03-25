// rule_engine/rules.rs — Rule table for Channel B
//
// Each Rule is a named predicate (fn(&str) -> RuleOutcome).
// No regex, no ML — pure structural and lexical analysis.
//
// Rule authoring contract:
//   • A rule MUST return Pass or Block for inputs it claims to handle.
//   • A rule MUST return Continue for inputs outside its scope.
//   • Rules are evaluated in declaration order — first non-Continue result wins.
//   • Rule IDs (RE-xxx) cross-reference with Safety Manual §6.

use super::RuleOutcome;
use crate::types::{BlockReason, MatchedIntent};

pub struct Rule {
    pub id: &'static str,
    pub description: &'static str,
    pub evaluate: fn(&str) -> RuleOutcome,
}

// ─── Helpers (no regex) ───────────────────────────────────────────────────────

fn word_count(s: &str) -> usize {
    s.split_whitespace().count()
}

fn starts_with_any_ci(s: &str, prefixes: &[&str]) -> bool {
    let lower = s.to_lowercase();
    prefixes.iter().any(|p| lower.starts_with(p))
}

fn contains_any_ci(s: &str, keywords: &[&str]) -> bool {
    let lower = s.to_lowercase();
    keywords.iter().any(|k| lower.contains(k))
}

fn ends_with_question_mark(s: &str) -> bool {
    s.trim_end().ends_with('?')
}

// ─── Rule Table ───────────────────────────────────────────────────────────────

pub static RULE_TABLE: &[Rule] = &[
    // ── Block rules (checked before allow rules) ─────────────────────────────

    Rule {
        id: "RE-001",
        description: "Block: suspiciously long single-word tokens (obfuscation attempt)",
        evaluate: |input| {
            let has_giant_token = input
                .split_whitespace()
                .any(|w| w.chars().count() > 512);
            if has_giant_token {
                RuleOutcome::Block(BlockReason::MalformedInput {
                    detail: "token exceeds 512 chars".into(),
                })
            } else {
                RuleOutcome::Continue
            }
        },
    },

    Rule {
        id: "RE-002",
        description: "Block: prompt injection markers (common injection prefixes)",
        evaluate: |input| {
            const INJECTION_MARKERS: &[&str] = &[
                "ignore previous instructions",
                "ignore all prior",
                "disregard your",
                "forget everything above",
                "your new instructions are",
                "system: you are now",
                "### new system prompt",
                "---\nsystem:",
                "[system]",
                "<|system|>",
                "<|im_start|>system",
            ];
            if contains_any_ci(input, INJECTION_MARKERS) {
                RuleOutcome::Block(BlockReason::ForbiddenPattern {
                    pattern_id: "RE-002-INJECTION",
                })
            } else {
                RuleOutcome::Continue
            }
        },
    },

    Rule {
        id: "RE-003",
        description: "Block: role-play / persona hijack attempts",
        evaluate: |input| {
            const HIJACK_PHRASES: &[&str] = &[
                "pretend you are",
                "act as if you are",
                "you are now",
                "roleplay as",
                "role-play as",
                "simulate being",
                "imagine you have no restrictions",
                "for educational purposes only, explain how to",
                "hypothetically, if you had to",
            ];
            if contains_any_ci(input, HIJACK_PHRASES) {
                RuleOutcome::Block(BlockReason::ForbiddenPattern {
                    pattern_id: "RE-003-HIJACK",
                })
            } else {
                RuleOutcome::Continue
            }
        },
    },

    // ── Allow rules (structural / lexical) ───────────────────────────────────

    Rule {
        id: "RE-010",
        description: "Allow: single-sentence factual question (ends with ?, ≤ 40 words)",
        evaluate: |input| {
            if ends_with_question_mark(input)
                && word_count(input) <= 40
                && starts_with_any_ci(input, &["what", "who", "where", "when", "which", "how many", "how much"])
            {
                RuleOutcome::Pass(MatchedIntent::QuestionFactual)
            } else {
                RuleOutcome::Continue
            }
        },
    },

    Rule {
        id: "RE-011",
        description: "Allow: causal question",
        evaluate: |input| {
            if ends_with_question_mark(input)
                && word_count(input) <= 60
                && starts_with_any_ci(input, &["why", "how does", "how do", "what causes"])
            {
                RuleOutcome::Pass(MatchedIntent::QuestionCausal)
            } else {
                RuleOutcome::Continue
            }
        },
    },

    Rule {
        id: "RE-012",
        description: "Allow: comparison request",
        evaluate: |input| {
            if contains_any_ci(input, &["compare", "versus", " vs ", "difference between"])
                && word_count(input) <= 80
            {
                RuleOutcome::Pass(MatchedIntent::QuestionComparative)
            } else {
                RuleOutcome::Continue
            }
        },
    },

    Rule {
        id: "RE-020",
        description: "Allow: code generation request (structural markers)",
        evaluate: |input| {
            let has_task_verb = contains_any_ci(
                input,
                &["write a", "create a", "generate a", "implement a", "build a", "code a"],
            );
            let has_code_noun = contains_any_ci(
                input,
                &["function", "class", "module", "script", "algorithm", "program", "snippet"],
            );
            if has_task_verb && has_code_noun && word_count(input) <= 100 {
                RuleOutcome::Pass(MatchedIntent::TaskCodeGeneration)
            } else {
                RuleOutcome::Continue
            }
        },
    },

    Rule {
        id: "RE-021",
        description: "Allow: summarisation request",
        evaluate: |input| {
            if contains_any_ci(input, &["summarize", "summarise", "summary", "tl;dr", "tldr", "key points"])
                && word_count(input) <= 60
            {
                RuleOutcome::Pass(MatchedIntent::TaskTextSummarisation)
            } else {
                RuleOutcome::Continue
            }
        },
    },

    Rule {
        id: "RE-022",
        description: "Allow: translation request",
        evaluate: |input| {
            if contains_any_ci(input, &["translate", "übersetz", "traduire"])
                && word_count(input) <= 80
            {
                RuleOutcome::Pass(MatchedIntent::TaskTranslation)
            } else {
                RuleOutcome::Continue
            }
        },
    },

    Rule {
        id: "RE-030",
        description: "Allow: short greeting (≤ 5 words, known greeting token)",
        evaluate: |input| {
            if word_count(input) <= 5
                && starts_with_any_ci(
                    input,
                    &["hi", "hello", "hey", "good morning", "good afternoon",
                      "good evening", "moin", "hallo", "servus"],
                )
            {
                RuleOutcome::Pass(MatchedIntent::ConversationalGreeting)
            } else {
                RuleOutcome::Continue
            }
        },
    },

    Rule {
        id: "RE-031",
        description: "Allow: short acknowledgement (≤ 4 words)",
        evaluate: |input| {
            if word_count(input) <= 4
                && starts_with_any_ci(input, &["ok", "okay", "thanks", "thank you", "danke", "got it", "sure"])
            {
                RuleOutcome::Pass(MatchedIntent::ConversationalAcknowledgement)
            } else {
                RuleOutcome::Continue
            }
        },
    },

    Rule {
        id: "RE-040",
        description: "Allow: system meta-query",
        evaluate: |input| {
            if contains_any_ci(
                input,
                &["what model", "what version", "who made you", "who built you", "what can you do"],
            ) && word_count(input) <= 20
            {
                RuleOutcome::Pass(MatchedIntent::SystemMetaQuery)
            } else {
                RuleOutcome::Continue
            }
        },
    },
];
