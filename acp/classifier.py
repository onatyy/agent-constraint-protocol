"""
Classification layer — the ONLY place that reads action.tool or raw param content.
Everything below this in the stack operates on primitives only.

Heuristics run in three layers:
  1. Tool verb     → structural intent  (read / write / exec / network)
  2. Param content → refinements       (destructive? sensitive? injection?)
  3. Path / URL    → access category   (protected path?)

To add a new tool: update classify_action() only.
To add a new primitive: update classify_action() + constraints.PRIMITIVE_CONSTRAINTS.
"""

from __future__ import annotations

import re
from typing import Any

from acp.types import Action, Primitive


# --- detection patterns ---

_PROTECTED_PATHS = (
    "/etc", "/root", "/boot", "/sys", "/proc",
    "/usr/bin", "/usr/sbin", "/var/run/secrets",
)

_SENSITIVE_RE = re.compile(
    r"(password|passwd|api[_\-]?key|secret|token|auth(?:orization)?|credential|private[_\-]?key)",
    re.IGNORECASE,
)

_DESTRUCTIVE_RE = re.compile(
    r"(?:"
    r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f"      # rm -rf / rm -fr
    r"|rm\s+-[a-zA-Z]*f[a-zA-Z]*r"
    r"|\bshutdown\b"
    r"|\breboot\b"
    r"|\bmkfs\b"
    r"|dd\s+if="
    r"|:\(\)\s*\{.*\}"                   # fork bomb
    r"|>\s*/dev/sd[a-z]"                 # disk wipe
    r")",
    re.IGNORECASE,
)

_INJECTION_RE = re.compile(
    r"(ignore\s+(?:(?:previous|above|all)\s+)+instructions"  # one or more keywords before "instructions"
    r"|you\s+are\s+now\s+a"
    r"|disregard\s+(your\s+)?system\s+prompt"
    r"|act\s+as\s+(if\s+you\s+(are|were)\s+)?(?!a\s+user))"
    r"|jailbreak",
    re.IGNORECASE,
)

# used by the T4 dynamic rule to detect suspicious path reads
_SENSITIVE_PATH_RE = re.compile(
    r"\.(ssh|gpg|aws|env)|secret|credential|token",
    re.IGNORECASE,
)


def _scan_params_for(pattern: re.Pattern[str], params: dict[str, Any]) -> bool:
    """Recursively scan param keys and values for a regex pattern."""
    for key, val in params.items():
        if pattern.search(str(key)):
            return True
        if isinstance(val, str) and pattern.search(val):
            return True
        if isinstance(val, dict) and _scan_params_for(pattern, val):
            return True
    return False


def classify_action(action: Action) -> frozenset[Primitive]:
    """
    Translate a raw action into a set of high-level primitives.

    Examples
    --------
    system.exec + "rm -rf /"   → {DESTRUCTIVE_OPERATION}
    file.write  + /etc/shadow  → {STATE_MODIFICATION, SENSITIVE_ACCESS}
    http.post   + api_key body → {STATE_MODIFICATION, NETWORK_EGRESS, DATA_EXFILTRATION}
    file.read   + notes.txt    → {READ_ONLY}
    """
    ps: set[Primitive] = set()

    verb = action.tool.split(".")[-1] if "." in action.tool else action.tool

    # layer 1: structural intent from tool verb
    if verb in ("read", "get"):
        ps.add(Primitive.READ_ONLY)

    if verb in ("write", "append", "update", "delete"):
        ps.add(Primitive.STATE_MODIFICATION)

    if verb == "exec":
        # exec starts as state_modification; refined below if destructive
        ps.add(Primitive.STATE_MODIFICATION)

    if verb in ("post", "put", "patch"):
        ps.add(Primitive.STATE_MODIFICATION)
        ps.add(Primitive.NETWORK_EGRESS)

    if verb == "get" and action.tool.startswith("http."):
        ps.add(Primitive.NETWORK_EGRESS)

    if verb == "query":
        # DB reads are elevated vs file reads — treated as state access
        ps.add(Primitive.STATE_MODIFICATION)

    # layer 2: content-based refinements
    cmd = str(action.params.get("command", ""))
    if cmd and _DESTRUCTIVE_RE.search(cmd):
        ps.add(Primitive.DESTRUCTIVE_OPERATION)
        ps.discard(Primitive.STATE_MODIFICATION)  # more specific primitive wins

    if _scan_params_for(_SENSITIVE_RE, action.params):
        ps.add(Primitive.DATA_EXFILTRATION)

    if _scan_params_for(_INJECTION_RE, action.params):
        ps.add(Primitive.PROMPT_INJECTION)

    # layer 3: path / URL sensitivity
    path = str(action.params.get("path", "") or action.params.get("url", ""))
    if any(path.startswith(p) for p in _PROTECTED_PATHS):
        ps.add(Primitive.SENSITIVE_ACCESS)

    return frozenset(ps)
