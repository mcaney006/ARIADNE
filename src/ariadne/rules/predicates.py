"""The single source of truth for what a field predicate *means*.

Both the surface DSL and the compiled IR describe predicates the same way, and
both the local engine and the SIEM compilers must agree on their semantics. That
agreement lives here. A predicate is a ``(field, op, value)`` triple; this module
knows how to evaluate one against an event and how to render it for humans and
for each query backend.

The operator vocabulary is intentionally Django/ORM-flavoured because detection
authors already know it::

    Event("process.execution").where(process_name__in={"zip", "7z"})
    Event("github.repository.clone").where(repository_sensitivity="restricted")
    Event("filesystem.write").where(path__regex=r"\\.env$")
"""

from __future__ import annotations

import re
from collections.abc import Collection
from typing import Any, Callable

from ariadne.events.schema import Event, resolve_field

#: Operator suffixes recognised on ``where(field__op=value)`` keyword arguments.
#: Order matters: longer tokens are tried first so ``not_in`` wins over ``in``.
OPERATOR_TOKENS: tuple[str, ...] = (
    "not_in",
    "gte",
    "lte",
    "startswith",
    "endswith",
    "contains",
    "exists",
    "regex",
    "in",
    "ne",
    "gt",
    "lt",
    "eq",
)


def split_operator(key: str) -> tuple[str, str]:
    """Split a ``where`` keyword into ``(field, op)``.

    ``process_name__in`` -> ``("process_name", "in")``;
    ``repository_sensitivity`` -> ``("repository_sensitivity", "eq")``.

    Field names keep their single underscores; only a trailing ``__<op>`` is
    interpreted as an operator.
    """

    if "__" in key:
        field, _, tail = key.rpartition("__")
        if tail in OPERATOR_TOKENS:
            return field, tail
    return key, "eq"


def _as_collection(value: Any) -> Collection[Any]:
    if isinstance(value, (set, frozenset, list, tuple)):
        return value
    return (value,)


def _cmp(op: Callable[[Any, Any], bool]) -> Callable[[Any, Any], bool]:
    def guarded(actual: Any, expected: Any) -> bool:
        if actual is None:
            return False
        try:
            return op(actual, expected)
        except TypeError:
            return False

    return guarded


_EVALUATORS: dict[str, Callable[[Any, Any], bool]] = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "in": lambda a, b: a in _as_collection(b),
    "not_in": lambda a, b: a not in _as_collection(b),
    "gt": _cmp(lambda a, b: a > b),
    "gte": _cmp(lambda a, b: a >= b),
    "lt": _cmp(lambda a, b: a < b),
    "lte": _cmp(lambda a, b: a <= b),
    "startswith": _cmp(lambda a, b: str(a).startswith(b)),
    "endswith": _cmp(lambda a, b: str(a).endswith(b)),
    "regex": _cmp(lambda a, b: re.search(b, str(a)) is not None),
    "exists": lambda a, b: (a is not None) == bool(b),
}


def _contains(actual: Any, expected: Any) -> bool:
    if actual is None:
        return False
    if isinstance(actual, (set, frozenset, list, tuple)):
        return expected in actual
    return expected in str(actual)


_EVALUATORS["contains"] = _contains


def evaluate(field: str, op: str, value: Any, event: Event) -> bool:
    """Return whether ``event`` satisfies a single predicate."""

    evaluator = _EVALUATORS.get(op)
    if evaluator is None:
        raise ValueError(f"unknown predicate operator: {op!r}")
    actual = resolve_field(event, field)
    return evaluator(actual, value)


_HUMAN_OPS: dict[str, str] = {
    "eq": "=",
    "ne": "≠",
    "in": "in",
    "not_in": "not in",
    "gt": ">",
    "gte": "≥",
    "lt": "<",
    "lte": "≤",
    "startswith": "starts with",
    "endswith": "ends with",
    "contains": "contains",
    "regex": "matches",
    "exists": "is present" ,
}


def describe(field: str, op: str, value: Any) -> str:
    """Render a predicate as a short human-readable phrase."""

    if op == "exists":
        return f"{field} {'is present' if value else 'is absent'}"
    rendered = _render_value(value)
    return f"{field} {_HUMAN_OPS.get(op, op)} {rendered}"


def _render_value(value: Any) -> str:
    if isinstance(value, (set, frozenset)):
        inner = ", ".join(_render_scalar(v) for v in sorted(value, key=str))
        return "{" + inner + "}"
    if isinstance(value, (list, tuple)):
        inner = ", ".join(_render_scalar(v) for v in value)
        return "[" + inner + "]"
    return _render_scalar(value)


def _render_scalar(value: Any) -> str:
    if isinstance(value, str):
        return repr(value)
    return str(value)
