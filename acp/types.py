"""
Core types — enums and dataclasses shared across the whole ACP system.
Nothing here imports from other acp modules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Decision(Enum):
    ALLOW  = "ALLOW"
    BLOCK  = "BLOCK"
    REVIEW = "REVIEW"


class Primitive(Enum):
    """
    High-level action primitives produced by the classifier.
    The enforcement layer operates only on these — never on action.tool directly.
    """
    DESTRUCTIVE_OPERATION = "destructive_operation"
    DATA_EXFILTRATION     = "data_exfiltration"
    SENSITIVE_ACCESS      = "sensitive_access"
    STATE_MODIFICATION    = "state_modification"
    NETWORK_EGRESS        = "network_egress"
    PROMPT_INJECTION      = "prompt_injection"
    READ_ONLY             = "read_only"


class ThreatCategory(Enum):
    """Maps scenarios to the threat model for metric analysis."""
    MALICIOUS_USER   = "T1-MaliciousUser"
    PROMPT_INJECTION = "T2-PromptInjection"
    JAILBREAK        = "T3-JailbreakAgent"
    MULTI_STEP       = "T4-MultiStep"
    BENIGN           = "T0-Benign"


class GroundTruth(Enum):
    """Expected correct decision for a scenario."""
    SAFE     = "SAFE"      # correct decision is ALLOW
    UNSAFE   = "UNSAFE"    # correct decision is BLOCK
    ELEVATED = "ELEVATED"  # correct decision is REVIEW


@dataclass
class Action:
    """A structured, validated agent action request."""
    tool:   str              # dot-namespaced: category.verb  (e.g. "file.write")
    params: dict[str, Any]  # tool-specific parameters
    label:  str = ""         # human-readable description for reporting


@dataclass
class ACPResult:
    """Complete output of the ACP engine for a single action."""
    decision:            Decision
    risk_score:          int
    primitives:          frozenset[Primitive]  = field(default_factory=frozenset)
    reasons:             list[str]             = field(default_factory=list)
    dynamic_constraints: list[str]             = field(default_factory=list)
    schema_errors:       list[str]             = field(default_factory=list)
    blocked_by:          str                   = ""
