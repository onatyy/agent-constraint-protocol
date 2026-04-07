"""
Risk scoring — primitive-based, no tool-specific logic here.
Scores generalise automatically to new tools as long as classify_action()
assigns the right primitives.
"""

from __future__ import annotations

from acp.types import Primitive


_PRIMITIVE_RISK: dict[Primitive, int] = {
    Primitive.DESTRUCTIVE_OPERATION: 85,
    Primitive.DATA_EXFILTRATION:     75,
    Primitive.PROMPT_INJECTION:      70,
    Primitive.SENSITIVE_ACCESS:      60,
    Primitive.NETWORK_EGRESS:        40,
    Primitive.STATE_MODIFICATION:    30,
    Primitive.READ_ONLY:             10,
}

REVIEW_THRESHOLD = 55   # score >= this → REVIEW (if no hard-block)


def compute_risk_score(primitives: frozenset[Primitive], extra_penalty: int = 0) -> int:
    """
    Numeric risk score 0–100.
    Base = highest-risk primitive present.
    Bonuses:
      - multiple high-risk (>=60) primitives co-occurring adds 5 pts each
      - NETWORK_EGRESS + STATE_MODIFICATION together adds 15 pts
        (data going out combined with state change is riskier than either alone)
    """
    if not primitives:
        return 10

    base = max(_PRIMITIVE_RISK.get(p, 25) for p in primitives)

    # bonus for multiple high-risk primitives co-occurring
    high_risk_count = sum(1 for p in primitives if _PRIMITIVE_RISK.get(p, 0) >= 60)
    combo_bonus = max(0, high_risk_count - 1) * 5

    # extra penalty for egress+mutation — outbound request combined with state change
    egress_mutation_bonus = 15 if (
        Primitive.NETWORK_EGRESS in primitives and
        Primitive.STATE_MODIFICATION in primitives
    ) else 0

    return min(base + combo_bonus + egress_mutation_bonus + extra_penalty, 100)
