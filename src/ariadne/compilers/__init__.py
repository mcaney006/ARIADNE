"""Backend compilers: one detection IR, many query languages.

Each compiler is a pass over the same :class:`~ariadne.rules.ast.DetectionIR`.
They emit best-effort, human-readable queries in their target dialect and are
honest about where a dialect cannot express ARIADNE's exact event-time semantics
(notably count thresholds and within-sequence negation), annotating those spots
rather than silently dropping them.
"""

from ariadne.compilers.clickhouse import compile_clickhouse
from ariadne.compilers.eql import compile_eql
from ariadne.compilers.kql import compile_kql
from ariadne.compilers.spl import compile_spl

#: Registry so the CLI can dispatch ``--target`` by name.
COMPILERS = {
    "eql": compile_eql,
    "spl": compile_spl,
    "kql": compile_kql,
    "clickhouse": compile_clickhouse,
}

__all__ = [
    "COMPILERS",
    "compile_clickhouse",
    "compile_eql",
    "compile_kql",
    "compile_spl",
]
