"""Shared rendering helpers for the backend compilers.

Field addressing and predicate rendering differ just enough between dialects to
warrant one small place that knows the differences. Keeping value quoting and
operator spelling here means the four compilers stay short and structurally
identical — each is essentially "walk the IR, render predicates, glue with the
dialect's sequence construct".
"""

from __future__ import annotations

from typing import Any

from ariadne.rules.ast import PredicateIR


def sql_column(field: str) -> str:
    """Map a dotted IR field to a flat SQL column (``actor.user_id`` -> ``actor_user_id``)."""

    return field.replace(".", "_")


def render_scalar(value: Any, *, quote: str = '"') -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return f"{quote}{value}{quote}"


def render_list(values: Any, *, quote: str = '"') -> str:
    items = sorted(values, key=str) if isinstance(values, (set, frozenset)) else list(values)
    return ", ".join(render_scalar(v, quote=quote) for v in items)


def render_predicate(predicate: PredicateIR, dialect: str) -> str:
    """Render one predicate in a given dialect (``eql``/``spl``/``kql``/``sql``)."""

    field = sql_column(predicate.field) if dialect in {"spl", "sql"} else predicate.field
    op = predicate.op
    value = predicate.value
    quote = "'" if dialect == "sql" else '"'

    if op == "eq":
        eq = "==" if dialect in {"eql", "kql"} else "="
        return f"{field} {eq} {render_scalar(value, quote=quote)}"
    if op == "ne":
        ne = "!=" if dialect in {"eql", "kql", "spl"} else "<>"
        return f"{field} {ne} {render_scalar(value, quote=quote)}"
    if op == "in":
        return f"{field} in ({render_list(value, quote=quote)})"
    if op == "not_in":
        return f"not {field} in ({render_list(value, quote=quote)})"
    if op in {"gt", "gte", "lt", "lte"}:
        symbol = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[op]
        return f"{field} {symbol} {render_scalar(value, quote=quote)}"
    if op == "contains":
        if dialect == "kql":
            return f'{field} contains {render_scalar(value, quote=quote)}'
        if dialect == "eql":
            return f'{field} : "*{value}*"'
        if dialect == "spl":
            return f'{field}="*{value}*"'
        return f"position({field}, {render_scalar(value, quote=quote)}) > 0"
    if op in {"startswith", "endswith"}:
        if dialect == "kql":
            return f"{field} {op} {render_scalar(value, quote=quote)}"
        wildcard = f"{value}*" if op == "startswith" else f"*{value}"
        if dialect == "eql":
            return f'{field} : "{wildcard}"'
        if dialect == "spl":
            return f'{field}="{wildcard}"'
        anchor = f"{value}%" if op == "startswith" else f"%{value}"
        return f"{field} LIKE {render_scalar(anchor, quote=quote)}"
    if op == "regex":
        if dialect == "kql":
            return f"{field} matches regex {render_scalar(value, quote=quote)}"
        if dialect == "eql":
            return f"{field} regex {render_scalar(value, quote=quote)}"
        if dialect == "spl":
            return f"match({field}, {render_scalar(value, quote=quote)})"
        return f"match({field}, {render_scalar(value, quote=quote)})"
    if op == "exists":
        present = bool(value)
        if dialect == "kql":
            return f"isnotnull({field})" if present else f"isnull({field})"
        if dialect == "sql":
            return f"{field} IS NOT NULL" if present else f"{field} IS NULL"
        return f"{field} != null" if present else f"{field} == null"
    raise ValueError(f"cannot render operator {op!r} for dialect {dialect!r}")


def render_conjunction(predicates: tuple[PredicateIR, ...], dialect: str, joiner: str = " and ") -> str:
    if not predicates:
        return "true"
    return joiner.join(render_predicate(p, dialect) for p in predicates)
