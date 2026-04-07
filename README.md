# Agent Constraint Protocol (ACP)

A deterministic, schema-validated, context-aware runtime enforcement layer for AI agent actions.

## The Problem

As AI agents gain access to tools — file systems, databases, external APIs, shell commands — the question of *what they're allowed to do* becomes critical. Most current approaches rely on probabilistic guardrails: LLM-based filtering, input/output classifiers, or training-time alignment. These are flexible but fundamentally non-deterministic. They can be bypassed, hallucinated around, or fail silently.

ACP takes a different approach: enforce constraints **structurally**, before execution, on every action, with a fully auditable decision trail. No language model in the enforcement path.

## Design Philosophy

ACP is built on two strictly separated layers:

**Classification** — translates raw action content (tool name, parameters, paths, commands) into a set of high-level *primitives* using heuristics. This layer is flexible and could be replaced by an ML model without touching anything below it.

**Enforcement** — operates only on primitives, never on the raw action tool directly. Deterministic and auditable by design. Adding a new tool requires updating only the classifier.

```
Action → [Classifier] → Primitives → [Enforcement] → Decision
```

## Threat Model

| ID | Threat | Description |
|----|--------|-------------|
| T1 | Malicious User | Crafts adversarial action parameters directly |
| T2 | Prompt Injection | External content redirects agent goals |
| T3 | Jailbroken Agent | Agent bypasses system-level instructions |
| T4 | Multi-Step Attack | Individually benign actions combine into harm |

## Architecture

```
acp/
  types.py        — Core enums and dataclasses (Action, ACPResult, Decision, Primitive)
  classifier.py   — Heuristic classification: Action → frozenset[Primitive]
  constraints.py  — Schema validation + static constraint functions
  risk.py         — Primitive-weighted risk scoring (0–100)
  dynamic.py      — Session-aware dynamic rules (cross-action pattern detection)
  engine.py       — 6-step evaluation pipeline

evaluation/
  scenarios.py    — Labelled test dataset (~52 scenarios across 5 categories)
  metrics.py      — MetricsTracker: SR, FPR, Review Precision
  runner.py       — Output formatting, per-category execution, results file

main.py           — Entry point
```

## Enforcement Pipeline

Each action goes through six steps:

1. **Schema validation** — malformed or unknown tools are auto-blocked
2. **Classification** — action mapped to primitives (e.g. `NETWORK_EGRESS`, `PROMPT_INJECTION`)
3. **Dynamic constraint generation** — session history inspected for multi-step patterns
4. **Static constraint evaluation** — primitive-keyed, hard-block on first violation
5. **Dynamic constraint evaluation** — cross-action pattern enforcement
6. **Risk scoring + decision** — primitive-weighted score → `ALLOW` / `REVIEW` / `BLOCK`

## Primitives

| Primitive | Risk Score | Description |
|-----------|-----------|-------------|
| `DESTRUCTIVE_OPERATION` | 85 | Irreversible harm (rm -rf, mkfs, fork bomb) |
| `DATA_EXFILTRATION` | 75 | Credential or secret material in params |
| `PROMPT_INJECTION` | 70 | Adversarial instruction embedding |
| `SENSITIVE_ACCESS` | 60 | Protected filesystem paths (/etc, /root, ...) |
| `NETWORK_EGRESS` | 40 | Outbound network traffic |
| `STATE_MODIFICATION` | 30 | Writes, appends, updates |
| `READ_ONLY` | 10 | Non-mutating operations |

Risk scores combine: base = highest primitive, with bonuses for co-occurring high-risk primitives and a +15 bonus when `NETWORK_EGRESS` and `STATE_MODIFICATION` co-occur (outbound + mutation is riskier than either alone). Score ≥ 55 triggers `REVIEW`.

## Dynamic Rules (T4 Detection)

Static constraints evaluate each action in isolation. Dynamic rules operate on session history:

- **SensitiveAccessThenEgress** — fires when an outbound request follows a sensitive-path read (e.g. reading `.ssh/known_hosts` then POSTing to an external endpoint)
- **ExecRateLimit** — blocks after 3 `system.exec` calls in one session
- **PathReuseAfterBlock** — blocks retry of a path that was previously blocked

## Evaluation Metrics

| Metric | Formula |
|--------|---------|
| Safety Rate (SR) | TP / (TP + FN) |
| False Positive Rate (FPR) | FP / (FP + TN) |
| Review Precision (RP) | correct reviews / total reviews |

The evaluation suite covers 52 scenarios across prompt injection, data exfiltration, destructive operations, benign actions, and schema validation.

## Positioning vs. Related Work

| System | Approach | Limitation |
|--------|----------|------------|
| NeMo Guardrails | LLM + Colang DSL | Probabilistic, LLM in critical path |
| LangChain safety | Per-tool wrappers | No cross-action session context |
| Constitutional AI | Training-time alignment | Not runtime enforcement |
| AutoGen safety | Execution sandboxing | Not generalised action constraint |

**ACP**: primitive-based classification + deterministic enforcement + context-aware dynamic constraints, with no LLM in the enforcement path.

## Running

```bash
python main.py
```

Runs the full evaluation suite and saves a timestamped results file (`results_YYYYMMDD_HHMMSS.txt`) in the working directory.

## Requirements

Python 3.10+, no external dependencies.
