import json
from pathlib import Path

import policy_gate


def call(name: str, *args):
    direct = getattr(policy_gate, name, None)
    if direct is not None:
        return direct(*args)

    legacy = getattr(policy_gate, f"firewall_{name}", None)
    if legacy is not None:
        return legacy(*args)

    raise AttributeError(
        f"policy_gate module has neither '{name}' nor 'firewall_{name}'. "
        "Rebuild/reinstall the Python wheel after binding changes."
    )


def main() -> None:
    corpus_path = Path(__file__).resolve().parent.parent / "verification" / "conformance_corpus.json"
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))

    call("init")

    for case in corpus["single"]:
        verdict = call("evaluate_raw", case["input"])
        assert verdict["verdict_kind"] == case["expected_kind"], (
            f"single:{case['name']} expected {case['expected_kind']}, got {verdict['verdict_kind']}"
        )

    for case in corpus["conversation"]:
        verdict = call("evaluate_messages", case["messages"])
        actual_first_block = verdict["first_block_index"]
        expected_first_block = case["expected_first_block_index"]
        assert verdict["is_pass"] == case["expected_is_pass"], (
            f"conversation:{case['name']} expected is_pass={case['expected_is_pass']}, got {verdict['is_pass']}"
        )
        assert actual_first_block == (expected_first_block if expected_first_block is not None else -1), (
            f"conversation:{case['name']} expected first_block_index={expected_first_block}, got {actual_first_block}"
        )

    for case in corpus["egress"]:
        verdict = call("evaluate_output", case["prompt"], case["response"])
        assert verdict["verdict_kind"] == case["expected_kind"], (
            f"egress:{case['name']} expected {case['expected_kind']}, got {verdict['verdict_kind']}"
        )

    print(
        {
            "status": "ok",
            "single": len(corpus["single"]),
            "conversation": len(corpus["conversation"]),
            "egress": len(corpus["egress"]),
        }
    )


if __name__ == "__main__":
    main()
