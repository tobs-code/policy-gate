use firewall_core::{evaluate_messages, evaluate_output, evaluate_raw, init, ChatMessage, PromptInput};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Corpus {
    single: Vec<SingleCase>,
    conversation: Vec<ConversationCase>,
    egress: Vec<EgressCase>,
}

#[derive(Debug, Deserialize)]
struct SingleCase {
    name: String,
    input: String,
    expected_kind: String,
}

#[derive(Debug, Deserialize)]
struct ConversationCase {
    name: String,
    messages: Vec<MessageCase>,
    expected_is_pass: bool,
    expected_first_block_index: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct MessageCase {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct EgressCase {
    name: String,
    prompt: String,
    response: String,
    expected_kind: String,
}

fn load_corpus() -> Corpus {
    serde_json::from_str(include_str!("../../../verification/conformance_corpus.json"))
        .expect("conformance corpus must parse")
}

#[test]
fn conformance_corpus_matches_core() {
    init().expect("init failed");
    let corpus = load_corpus();

    for (index, case) in corpus.single.iter().enumerate() {
        let verdict = evaluate_raw(case.input.clone(), index as u64 + 1);
        assert_eq!(
            format!("{:?}", verdict.kind),
            case.expected_kind,
            "single case '{}' drifted",
            case.name
        );
    }

    for (index, case) in corpus.conversation.iter().enumerate() {
        let messages: Vec<ChatMessage> = case
            .messages
            .iter()
            .map(|message| ChatMessage {
                role: message.role.clone(),
                content: message.content.clone(),
            })
            .collect();
        let verdict = evaluate_messages(&messages, 10_000 + index as u64);
        assert_eq!(
            verdict.is_pass,
            case.expected_is_pass,
            "conversation case '{}' drifted on is_pass",
            case.name
        );
        assert_eq!(
            verdict.first_block_index,
            case.expected_first_block_index,
            "conversation case '{}' drifted on first_block_index",
            case.name
        );
    }

    for (index, case) in corpus.egress.iter().enumerate() {
        let prompt = PromptInput::new(case.prompt.clone()).expect("egress prompt must normalise");
        let verdict = evaluate_output(&prompt, &case.response, 20_000 + index as u64)
            .expect("egress evaluation must succeed");
        assert_eq!(
            format!("{:?}", verdict.kind),
            case.expected_kind,
            "egress case '{}' drifted",
            case.name
        );
    }
}
