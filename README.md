# policy-gate

Deterministic firewall for LLM applications, agents, and AI gateways.

Instead of trying to guess whether a prompt is dangerous, `policy-gate` only permits explicitly allowlisted intents. Unknown, ambiguous, or policy-violating inputs fail closed.

It is designed for teams that want predictable enforcement, auditable decisions, and a narrow control boundary around model access.

**Status:** Under development. Not certified. Not for production use.  
**Important:** This project borrows architectural ideas from functional safety engineering, but it is not an IEC 61508 implementation and makes no certification or compliance claims.

## At a glance

- deterministic allowlist-first enforcement
- fail-closed behavior on ambiguity, disagreement, or fault
- auditable PASS/BLOCK outcomes
- advisory heuristics and semantic analysis kept outside the safety path
- Rust core with Node, Python, and WASM targets

## Why this project exists

Most AI guardrails are probabilistic classifiers. They can be useful, but they are often hard to reason about, hard to audit, and difficult to bound in high-control environments.

`policy-gate` takes a narrower approach:

- allow only known-good intent shapes
- block unknown or ambiguous requests by default
- keep the safety path deterministic
- treat AI-assisted analysis as advisory, not authoritative
- produce audit records for every decision

The core idea is simple: for some systems, it is better to make unsafe requests unrepresentable than to estimate whether they look risky.

## Best first use case

The best fit is an internal or customer-facing AI workflow where only a small, well-defined set of user intents should ever reach the model or downstream tools.

Examples:

- fronting an agent that can call tools or execute multi-step workflows
- enforcing tenant- or profile-specific prompt policies
- validating model output for prompt leakage, credential leakage, or PII
- creating a reviewable PASS/BLOCK layer in front of LLM APIs

## Quick example

### TypeScript

```ts
import { Firewall } from "policy-gate";

const firewall = await Firewall.create({
  onAudit: async (entry) => {
    await db.audit.insert(entry);
  },
});

const verdict = await firewall.evaluate("What is the capital of France?");

if (!verdict.isPass) {
  throw new Error(`Blocked: ${verdict.blockReason}`);
}

// safe to forward to the model
```

### Python

```python
import policy_gate

policy_gate.init()

verdict = policy_gate.evaluate_raw("What is the capital of France?")

if not verdict["is_pass"]:
    raise RuntimeError(f"Blocked: {verdict['block_reason']}")
```

## How it works

At a high level, the firewall:

1. normalizes and hardens the input before policy evaluation
2. evaluates it through independent deterministic channels
3. votes fail-closed on disagreements or faults
4. records an audit entry for review and analytics
5. can also validate model output against leakage and PII rules

## Architecture at a glance

```text
prompt
  -> normalization and structural hardening
  -> Channel A: FSM + allowlist matching
  -> Channel B: rule engine
  -> 1oo2-inspired fail-closed voter
  -> PASS / BLOCK + audit record
  -> Channel C advisory analysis (post-verdict, non-authoritative)
  -> Channel D semantic similarity (optional, advisory-only)
```

For egress validation, the same philosophy is applied to model responses through a separate two-channel path focused on leakage, framing patterns, and PII-like output.

## Design principles

- Deterministic safety path: the verdict does not depend on an LLM.
- Fail closed: unknowns, disagreements, and internal faults block.
- Channel diversity: the main channels use different techniques to reduce common-mode failure.
- Advisory isolation: heuristic and semantic signals never override the safety decision.
- Auditable operation: every decision can be recorded and analyzed later.

## Main components

### Channel A: FSM + allowlist

Channel A is a finite state machine with explicit tokenization, forbidden-pattern checks, and allowlist matching. It includes a watchdog and returns `Fault` on deadline violations, which the voter treats as `Block`.

### Channel B: Rule engine

Channel B performs structural and lexical analysis without regex or ML in its core rule path. Block rules are evaluated before allow rules.

### Channel C: advisory heuristics

This channel runs after the verdict and stores non-authoritative heuristics in the audit trail. It is useful for operator review, investigation, and tuning, but it does not gate the decision.

### Channel D: semantic similarity

This is an optional advisory feature. Default builds keep it disabled. The current implementation uses a lightweight static subword-embedding path and writes similarity information to the audit log without changing PASS/BLOCK outcomes.

### Egress firewall

The output side validates model responses against the original prompt and checks for leakage, framing signals, and PII-like content. It uses a two-channel fail-closed design separate from the ingress path.

## Why it feels different from typical guardrails

- It is closer to a policy firewall than a prompt classifier.
- It optimizes for narrow, explainable control boundaries rather than broad conversational flexibility.
- It is designed around reviewability, diagnostics, and regression testing.
- It treats semantic analysis as support tooling, not as the safety kernel.

## Who it is for

- teams building agents with tool use or multi-step workflows
- platform engineers adding a control layer in front of LLM APIs
- security-minded builders who prefer deterministic policy enforcement
- researchers exploring high-assurance guardrail architectures

## Project layout

```text
policy-gate/
├── crates/
│   ├── firewall-core/     # Rust safety kernel
│   ├── firewall-cli/      # CLI for benchmarks and verification flows
│   ├── firewall-napi/     # Node native binding
│   ├── firewall-pyo3/     # Python binding
│   ├── firewall-wasm/     # WASM / edge target
│   └── firewall-fuzz/     # fuzz targets
├── scripts/               # smoke + conformance scripts
├── verification/          # Z3 models, corpora, analytics, benchmarks
├── deployment.md          # deployment notes
├── SAFETY_MANUAL.md       # deeper design and safety documentation
└── firewall.example.toml  # example configuration
```

## Supported runtimes

- Rust core library
- Node.js via `napi-rs`
- Python via `PyO3` and `maturin`
- WASM / edge builds

The safety function lives in Rust. The Node and Python packages are bindings around that core.

## Quickstart

### Node / TypeScript

```bash
npm install
npm run build:native
npm run build
npm run smoke
npm run conformance
```

Notes:

- `npm run build:native` builds the `firewall-napi` module and copies it to `native/index.node`.
- `npm run build` compiles [index.ts](./index.ts).
- `npm run smoke` exercises the basic wrapper paths.
- `npm run conformance` runs the shared corpus in [verification/conformance_corpus.json](./verification/conformance_corpus.json).

If the native `.node` file is not present yet, the wrapper falls back to a deterministic development stub.

### Python

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install maturin
python -m maturin develop --manifest-path crates/firewall-pyo3/Cargo.toml
python scripts/smoke.py
python scripts/conformance.py
```

If you prefer wheel-based installation:

```powershell
python -m pip install maturin
python -m maturin build --manifest-path crates/firewall-pyo3/Cargo.toml
$wheel = (Get-ChildItem .\target\wheels\*.whl | Select-Object -First 1).FullName
python -m pip install $wheel
python scripts\smoke.py
python scripts\conformance.py
```

### Rust core

```bash
cargo test -p firewall-core
cargo clippy -p firewall-core -- -D warnings
```

### Semantic feature compile check

```bash
cargo check -p firewall-core --features semantic
```

### WASM / edge

The workspace includes `crates/firewall-wasm` for edge and browser-oriented builds where the semantic feature remains disabled.

## API surface

The Rust core exposes APIs for:

- single prompt evaluation
- raw input evaluation
- multi-message conversation evaluation
- output / egress evaluation
- profile-based initialization
- audit review tracking

The bindings expose matching subsets of that behavior for Node and Python.

## Configuration and profiles

The project supports:

- default and profile-based initialization
- custom intent patterns
- tenant-specific policy configuration
- TOML-based configuration via [firewall.example.toml](./firewall.example.toml)

The design is multi-tenant at the policy layer and single-tenant at the safety decision core.

## Verification and testing

Verification is a major part of the project rather than an afterthought.

### Automated checks in the repo

- Rust test suite for core behavior and regressions
- smoke and conformance checks for Node and Python bindings
- fuzz targets in `crates/firewall-fuzz`
- dataset regressions for harmful prompts
- false-positive rate measurement
- CI security auditing with `cargo-audit`

### Formal verification

The repository includes Z3 models for critical invariants:

- [verification/channel_a.smt2](./verification/channel_a.smt2)
- [verification/voter.smt2](./verification/voter.smt2)
- [verification/rule_engine.smt2](./verification/rule_engine.smt2)

Run them with:

```bash
python verification/run_proofs.py
```

There is also a pattern-change tripwire:

```bash
python verification/check_pattern_hash.py
```

### Regression datasets

```bash
cargo build --release -p firewall-cli
python verification/benchmark_datasets.py
python verification/fp_rate_test.py
```

### Review and analytics tooling

The repository also includes operator-facing support tooling:

- [verification/operator_review.py](./verification/operator_review.py)
- [verification/disagreement_analytics.py](./verification/disagreement_analytics.py)
- [verification/operator_review_architecture.md](./verification/operator_review_architecture.md)

## Hardening themes

The codebase contains explicit hardening work for areas such as:

- prompt injection markers and chat-template abuse
- obfuscation via Unicode confusables, combining marks, bidi controls, and separators
- low-and-slow probing detection through analytics
- watchdog behavior and fail-closed fault handling
- leakage and PII-like output validation
- audit integrity via chained HMAC-based records

For the full design history and safety action log, see [SAFETY_MANUAL.md](./SAFETY_MANUAL.md).

## Limitations

`policy-gate` is intentionally narrow.

- It is not a general-purpose conversational safety solution.
- It works best when the allowed intent space is small and explicit.
- A deterministic allowlist-first design trades flexibility for predictability.
- Advisory semantic analysis is helpful, but it is not the trust anchor.
- The project is still under development and not appropriate for production or safety-critical deployment.

## When to use it

Use it when you want:

- a strict policy gate in front of model access
- deterministic PASS/BLOCK behavior
- auditable decisions and review workflows
- a defense-oriented wrapper around tool-using agents

It is a weaker fit when you want:

- broad open-ended chatbot moderation
- nuanced intent classification over a large unconstrained prompt space
- a drop-in replacement for human review or policy design

## Related docs

- [SAFETY_MANUAL.md](./SAFETY_MANUAL.md)
- [deployment.md](./deployment.md)
- [RED_TEAM.md](./RED_TEAM.md)

## License

Apache License 2.0. See [LICENSE](./LICENSE).
