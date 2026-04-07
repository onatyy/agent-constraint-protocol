"""
ACP Engine — orchestrates the full evaluation pipeline.

Pipeline steps:
  1. Schema validation        — malformed actions auto-blocked
  2. Classification           — action → primitives  (flexible layer)
  3. Dynamic constraint gen   — session history → injected constraints
  4. Static constraint eval   — primitive-keyed, hard-block on first hit
  5. Dynamic constraint eval  — cross-action patterns
  6. Risk scoring + decision  — primitive-weighted, BLOCK > REVIEW > ALLOW
"""

from __future__ import annotations

from acp.types import Action, ACPResult, Decision
from acp.classifier import classify_action
from acp.constraints import validate_schema, get_constraints
from acp.risk import compute_risk_score, REVIEW_THRESHOLD
from acp.dynamic import SessionContext, apply_dynamic_constraints


def evaluate(action: Action, ctx: SessionContext | None = None) -> ACPResult:
    """Run a single action through the full ACP pipeline."""
    if ctx is None:
        ctx = SessionContext()

    # step 1: schema validation
    schema_errors = validate_schema(action)
    if schema_errors:
        result = ACPResult(
            decision      = Decision.BLOCK,
            risk_score    = 100,
            primitives    = frozenset(),
            schema_errors = schema_errors,
            blocked_by    = "SchemaValidator",
            reasons       = [f"Schema violation: {e}" for e in schema_errors],
        )
        ctx.record(action, result)
        return result

    # step 2: classify → primitives
    primitives = classify_action(action)

    # step 3: generate dynamic constraints based on session history
    dynamic_fns, risk_penalty = apply_dynamic_constraints(action, primitives, ctx)
    dynamic_labels = [label for _, label in dynamic_fns]

    # step 4: run static constraints — hard-block on first violation
    reasons:    list[str] = []
    blocked_by: str       = ""

    for constraint_fn, is_hard_block in get_constraints(primitives):
        violated, reason = constraint_fn(action, primitives)
        if violated:
            reasons.append(reason)
            if is_hard_block:
                blocked_by = constraint_fn.__name__
                result = ACPResult(
                    decision            = Decision.BLOCK,
                    risk_score          = compute_risk_score(primitives, risk_penalty),
                    primitives          = primitives,
                    reasons             = reasons,
                    dynamic_constraints = dynamic_labels,
                    blocked_by          = blocked_by,
                )
                ctx.record(action, result)
                return result

    # step 5: run dynamic constraints
    for dyn_fn, dyn_label in dynamic_fns:
        violated, reason = dyn_fn(action, primitives)
        if violated:
            reasons.append(reason)
            result = ACPResult(
                decision            = Decision.BLOCK,
                risk_score          = compute_risk_score(primitives, risk_penalty),
                primitives          = primitives,
                reasons             = reasons,
                dynamic_constraints = dynamic_labels,
                blocked_by          = dyn_label,
            )
            ctx.record(action, result)
            return result

    # step 6: risk score → final decision
    risk_score = compute_risk_score(primitives, risk_penalty)

    if risk_score >= REVIEW_THRESHOLD:
        reasons.append(
            f"Risk score {risk_score} meets or exceeds review threshold ({REVIEW_THRESHOLD})"
        )
        decision = Decision.REVIEW
    else:
        decision = Decision.ALLOW

    result = ACPResult(
        decision            = decision,
        risk_score          = risk_score,
        primitives          = primitives,
        reasons             = reasons,
        dynamic_constraints = dynamic_labels,
    )
    ctx.record(action, result)
    return result
