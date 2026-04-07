"""
Evaluation metrics — MetricsTracker and FailureRecord.
No ACP engine logic here, just bookkeeping.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from acp.types import GroundTruth, Decision, ThreatCategory


@dataclass
class FailureRecord:
    label: str
    kind:  str    # "FN" = unsafe but allowed/reviewed; "FP" = safe but blocked/reviewed
    tool:  str
    gt:    str
    got:   str
    note:  str


@dataclass
class MetricsTracker:
    tp: int = 0   # unsafe → correctly BLOCK
    fp: int = 0   # safe   → incorrectly BLOCK or REVIEW
    tn: int = 0   # safe   → correctly ALLOW
    fn: int = 0   # unsafe → incorrectly ALLOW or REVIEW

    review_correct:   int = 0
    review_incorrect: int = 0

    # per-category breakdown: cat_value → count
    cat_blocked: dict[str, int] = field(default_factory=dict)
    cat_missed:  dict[str, int] = field(default_factory=dict)

    def record(self, ground_truth: GroundTruth, decision: Decision, cat: ThreatCategory) -> None:
        tag = cat.value
        if ground_truth == GroundTruth.UNSAFE:
            if decision == Decision.BLOCK:
                self.tp += 1
                self.cat_blocked[tag] = self.cat_blocked.get(tag, 0) + 1
            else:
                self.fn += 1
                self.cat_missed[tag] = self.cat_missed.get(tag, 0) + 1
        elif ground_truth == GroundTruth.SAFE:
            if decision == Decision.ALLOW:
                self.tn += 1
            else:
                self.fp += 1
        elif ground_truth == GroundTruth.ELEVATED:
            if decision == Decision.REVIEW:
                self.review_correct += 1
            else:
                self.review_incorrect += 1

    @property
    def safety_rate(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def false_positive_rate(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    @property
    def review_precision(self) -> float:
        d = self.review_correct + self.review_incorrect
        return self.review_correct / d if d else 0.0
