"""
Dynamic constraint engine — cross-action, session-aware enforcement.

Static constraints evaluate each action in isolation. Dynamic constraints
inspect session history and can detect multi-step attack patterns (T4)
that no single-action constraint can catch.

Rule results are cached in the session so the same rule doesn't recompute
if it fires more than once in a session.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from acp.types import Action, ACPResult, Primitive, Decision
from acp.classifier import _SENSITIVE_PATH_RE
from acp.constraints import ConstraintFn, get_constraints


@dataclass
class SessionContext:
    """Tracks action/result/primitive history for a single agent session."""
    history:      list[tuple[Action, ACPResult]] = field(default_factory=list)
    _rule_cache:  dict[str, tuple]               = field(default_factory=dict)   # name → (fn, label, penalty)
    _fired_rules: list[str]                      = field(default_factory=list)

    def record(self, action: Action, result: ACPResult) -> None:
        self.history.append((action, result))

    def past_primitives(self) -> set[Primitive]:
        """All primitives seen across the session so far."""
        return {p for _, r in self.history for p in r.primitives}

    def past_paths(self) -> list[str]:
        return [
            a.params.get("path", "") for a, _ in self.history
            if "path" in a.params
        ]

    def exec_count(self) -> int:
        """Number of system.exec actions in this session (tool check is intentional here)."""
        return sum(1 for a, _ in self.history if a.tool == "system.exec")

    def cache_rule(self, name: str, entry: tuple) -> None:
        """Cache a rule result so we don't recompute if the same pattern fires again."""
        if name not in self._rule_cache:
            self._rule_cache[name] = entry

    def get_cached_rule(self, name: str) -> tuple | None:
        return self._rule_cache.get(name)

    def note_fired(self, name: str) -> None:
        self._fired_rules.append(name)


@dataclass
class DynamicRule:
    """
    A single dynamic constraint rule.
      fires()    → should this rule activate for the current action + history?
      generate() → returns a constraint to inject + a risk penalty.
    """
    name:        str
    description: str
    fires:       Callable[[Action, frozenset[Primitive], SessionContext], bool]
    generate:    Callable[[Action, SessionContext], tuple[ConstraintFn, str, int]]


def _rule_sensitive_read_then_exfil() -> DynamicRule:
    """
    T4: agent accesses a sensitive-looking path, then attempts outbound network.
    Uses path heuristics (not just SENSITIVE_ACCESS) to catch paths like
    .ssh/known_hosts that aren't in _PROTECTED_PATHS.
    """
    def fires(_: Action, primitives: frozenset[Primitive], ctx: SessionContext) -> bool:
        if Primitive.NETWORK_EGRESS not in primitives:
            return False
        past_has_protected     = Primitive.SENSITIVE_ACCESS in ctx.past_primitives()
        past_has_sensitive_path = any(
            _SENSITIVE_PATH_RE.search(p) for p in ctx.past_paths() if p
        )
        return past_has_protected or past_has_sensitive_path

    def generate(_: Action, ctx: SessionContext) -> tuple[ConstraintFn, str, int]:
        del ctx
        def constraint(_: Action, primitives: frozenset[Primitive]) -> tuple[bool, str]:
            del primitives
            return (
                True,
                "Dynamic[T4]: outbound request follows a sensitive-path access — "
                "potential multi-step exfiltration",
            )
        return constraint, "SensitiveAccessThenEgress", 25

    return DynamicRule(
        name        = "SensitiveAccessThenEgress",
        description = "Block network egress that follows a sensitive-path access",
        fires       = fires,
        generate    = generate,
    )


def _rule_exec_rate_limit() -> DynamicRule:
    """
    T3: too many system.exec calls in one session → potential shell-proxy abuse.
    fires() checks action.tool — exec rate limiting is tool-specific by definition.
    """
    EXEC_LIMIT = 3  # allow up to 3, block on the 4th+

    def fires(action: Action, _: frozenset[Primitive], ctx: SessionContext) -> bool:
        return action.tool == "system.exec" and ctx.exec_count() >= EXEC_LIMIT

    def generate(_: Action, ctx: SessionContext) -> tuple[ConstraintFn, str, int]:
        count = ctx.exec_count()
        def constraint(_: Action, primitives: frozenset[Primitive]) -> tuple[bool, str]:
            del primitives
            return (
                True,
                f"Dynamic[T3]: session exec count ({count}) exceeds limit "
                f"({EXEC_LIMIT}) — potential shell-proxy abuse",
            )
        return constraint, "ExecRateLimit", 20

    return DynamicRule(
        name        = "ExecRateLimit",
        description = f"Escalate system.exec after >{EXEC_LIMIT} calls per session",
        fires       = fires,
        generate    = generate,
    )


def _rule_path_reuse_after_block() -> DynamicRule:
    """T1 persistence: re-access to a path involved in a previously blocked action."""
    def fires(action: Action, _: frozenset[Primitive], ctx: SessionContext) -> bool:
        current_path = action.params.get("path", "")
        if not current_path:
            return False
        blocked_paths = {
            a.params.get("path", "")
            for a, r in ctx.history
            if r.decision == Decision.BLOCK
        }
        return current_path in blocked_paths

    def generate(action: Action, _: SessionContext) -> tuple[ConstraintFn, str, int]:
        path = action.params.get("path", "")
        def constraint(_: Action, primitives: frozenset[Primitive]) -> tuple[bool, str]:
            del primitives
            return (
                True,
                f"Dynamic[T1]: path '{path}' was involved in a previously blocked "
                f"action — re-access flagged",
            )
        return constraint, "PathReuseAfterBlock", 30

    return DynamicRule(
        name        = "PathReuseAfterBlock",
        description = "Flag re-access to a path that appeared in a blocked action",
        fires       = fires,
        generate    = generate,
    )


DYNAMIC_RULES: list[DynamicRule] = [
    _rule_sensitive_read_then_exfil(),
    _rule_exec_rate_limit(),
    _rule_path_reuse_after_block(),
]


def _is_redundant(_: str, existing: list[tuple[ConstraintFn, bool]]) -> bool:
    """
    Redundancy check before injecting a dynamic constraint.
    Current rules target cross-action patterns not covered by static constraints,
    so no redundancies exist in practice.
    """
    del existing
    return False


def apply_dynamic_constraints(
    action:     Action,
    primitives: frozenset[Primitive],
    ctx:        SessionContext,
) -> tuple[list[tuple[ConstraintFn, str]], int]:
    """
    Evaluate all dynamic rules; return constraints to inject + total risk penalty.
    Reuses cached results when the same pattern fires more than once in a session.
    """
    injected:      list[tuple[ConstraintFn, str]] = []
    total_penalty: int                             = 0

    for rule in DYNAMIC_RULES:
        if rule.fires(action, primitives, ctx):
            # reuse cached result if this rule already fired earlier in the session
            cached = ctx.get_cached_rule(rule.name)
            if cached:
                fn, label, penalty = cached
            else:
                fn, label, penalty = rule.generate(action, ctx)
                ctx.cache_rule(rule.name, (fn, label, penalty))

            ctx.note_fired(rule.name)

            if not _is_redundant(label, get_constraints(primitives)):
                injected.append((fn, label))
                total_penalty += penalty

    return injected, total_penalty
