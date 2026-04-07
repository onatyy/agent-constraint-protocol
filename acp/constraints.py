"""
Static constraints — deterministic enforcement layer.

Each constraint is a pure function:
  (action, primitives) -> (violated: bool, reason: str)

Constraints gate on primitives only; they never check action.tool directly.
They may read action.params for reporting (e.g. which path triggered it),
but the decision to run at all is fully driven by the primitive set.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from acp.types import Action, Primitive
from acp.classifier import _SENSITIVE_RE, _INJECTION_RE

# type alias used here and in dynamic.py
ConstraintFn = Callable[["Action", frozenset[Primitive]], tuple[bool, str]]


# ---- schema validation ----

TOOL_SCHEMA: dict[str, set[str]] = {
    "file.read":    {"path"},
    "file.write":   {"path", "content"},
    "file.append":  {"path", "content"},
    "file.delete":  {"path"},
    "system.exec":  {"command"},
    "http.get":     {"url"},
    "http.post":    {"url", "body"},
    "db.query":     {"query"},
}

_TOOL_PATTERN = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")


def validate_schema(action: Action) -> list[str]:
    """Returns schema violation strings; empty list means well-formed."""
    errors: list[str] = []

    if not _TOOL_PATTERN.match(action.tool):
        errors.append(f"Invalid tool identifier '{action.tool}' (expected 'category.verb')")
        return errors

    if action.tool not in TOOL_SCHEMA:
        errors.append(f"Unknown tool '{action.tool}' — not in registered schema")
        return errors

    missing = TOOL_SCHEMA[action.tool] - action.params.keys()
    if missing:
        errors.append(f"Missing required params for '{action.tool}': {sorted(missing)}")

    return errors


# ---- simulated file registry ----

# files assumed to already exist on disk
_EXISTING_FILES: set[str] = {
    "/home/user/report.txt",
    "/var/log/app.log",
    "/tmp/cache.json",
    "/home/user/config.yaml",
    "/home/user/.ssh/known_hosts",
}


# ---- constraint functions ----

def c_destructive_operation(action: Action, primitives: frozenset[Primitive]) -> tuple[bool, str]:
    """T1/T3 — Block any action classified as destructive."""
    if Primitive.DESTRUCTIVE_OPERATION not in primitives:
        return False, ""
    cmd = str(action.params.get("command", action.tool))
    return True, f"Destructive operation detected: '{cmd[:80]}'"


def c_file_overwrite(action: Action, primitives: frozenset[Primitive]) -> tuple[bool, str]:
    """T1 — Prevent silent overwrites of registered files."""
    if Primitive.STATE_MODIFICATION not in primitives:
        return False, ""
    path = action.params.get("path", "")
    if path in _EXISTING_FILES:
        return True, f"Overwrite of existing file is not permitted: '{path}'"
    return False, ""


def c_sensitive_data(action: Action, primitives: frozenset[Primitive]) -> tuple[bool, str]:
    """T1/T2 — Block when DATA_EXFILTRATION is present; reports which field triggered it."""
    if Primitive.DATA_EXFILTRATION not in primitives:
        return False, ""

    def _find(params: dict[str, Any], prefix: str = "") -> str:
        for key, val in params.items():
            full_key = f"{prefix}.{key}" if prefix else key
            if _SENSITIVE_RE.search(str(key)):
                return full_key
            if isinstance(val, str) and _SENSITIVE_RE.search(val):
                return f"{full_key} (value)"
            if isinstance(val, dict):
                hit = _find(val, full_key)
                if hit:
                    return hit
        return "unknown field"

    return True, f"Sensitive data in '{_find(action.params)}'"


def c_protected_path(action: Action, primitives: frozenset[Primitive]) -> tuple[bool, str]:
    """T1/T3 — Block access when SENSITIVE_ACCESS is present."""
    if Primitive.SENSITIVE_ACCESS not in primitives:
        return False, ""
    path = str(action.params.get("path", "") or action.params.get("url", ""))
    return True, f"Access to protected path '{path}' is denied"


def c_prompt_injection(action: Action, primitives: frozenset[Primitive]) -> tuple[bool, str]:
    """T2 — Block when PROMPT_INJECTION is present; reports which param triggered it."""
    if Primitive.PROMPT_INJECTION not in primitives:
        return False, ""
    for key, val in action.params.items():
        if isinstance(val, str) and _INJECTION_RE.search(val):
            return True, f"Prompt-injection pattern in param '{key}'"
        if isinstance(val, dict):
            for inner_key, inner_val in val.items():
                if isinstance(inner_val, str) and _INJECTION_RE.search(inner_val):
                    return True, f"Prompt-injection pattern in nested param '{inner_key}'"
    return True, "Prompt-injection pattern detected"


def c_external_network(action: Action, primitives: frozenset[Primitive]) -> tuple[bool, str]:
    """T1 — Soft flag for NETWORK_EGRESS to unrecognised external domains (no hard-block)."""
    if Primitive.NETWORK_EGRESS not in primitives:
        return False, ""
    url = str(action.params.get("url", ""))
    if "example-internal.com" not in url and "localhost" not in url:
        return True, f"Outbound request to external endpoint: '{url}'"
    return False, ""


# ---- constraint registry keyed by primitive ----

PRIMITIVE_CONSTRAINTS: dict[Primitive, list[tuple[ConstraintFn, bool]]] = {
    Primitive.DESTRUCTIVE_OPERATION: [(c_destructive_operation, True)],
    Primitive.DATA_EXFILTRATION:     [(c_sensitive_data,        True)],
    Primitive.SENSITIVE_ACCESS:      [(c_protected_path,        True)],
    Primitive.STATE_MODIFICATION:    [(c_file_overwrite,        True)],
    Primitive.NETWORK_EGRESS:        [(c_external_network,      False)],  # soft flag
    Primitive.PROMPT_INJECTION:      [(c_prompt_injection,      True)],
    Primitive.READ_ONLY:             [],  # no blocking constraints for pure reads
}


def get_constraints(primitives: frozenset[Primitive]) -> list[tuple[ConstraintFn, bool]]:
    """Return the deduplicated constraint list for a primitive set."""
    seen:   set[ConstraintFn]               = set()
    result: list[tuple[ConstraintFn, bool]] = []
    for primitive in primitives:
        for fn, hard_block in PRIMITIVE_CONSTRAINTS.get(primitive, []):
            if fn not in seen:
                seen.add(fn)
                result.append((fn, hard_block))
    return result
