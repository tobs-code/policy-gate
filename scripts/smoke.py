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
    call("init")

    verdict = call("evaluate_raw", "What is the capital of France?")
    conversation = call(
        "evaluate_messages",
        [
            {"role": "user", "content": "Hello!"},
            {"role": "user", "content": "What is the capital of France?"},
        ],
    )
    egress = call(
        "evaluate_output",
        "What is the capital of France?",
        "The capital of France is Paris.",
    )

    print(
        {
            "evaluate": verdict["verdict_kind"],
            "conversation": {
                "is_pass": conversation["is_pass"],
                "verdict_count": len(conversation["verdicts"]),
            },
            "egress": egress["verdict_kind"],
        }
    )


if __name__ == "__main__":
    main()
