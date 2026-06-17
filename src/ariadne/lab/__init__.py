"""Synthetic telemetry generation for ARIADNE's scenarios and benchmarks.

``ariadne.lab`` is the *code* that fabricates realistic, deterministic event
streams — a synthetic enterprise of employees, devices, and the benign noise they
generate, plus the three flagship incidents threaded through it. The repository's
top-level ``lab/`` directory holds the operational assets (docker-compose, the
shell scenario actions) that exercise real decoy resources; this package is what
the Python scenario builders import.
"""

from ariadne.lab.synthetic import (
    SyntheticEnterprise,
    background_noise,
    make_event,
    write_jsonl,
)

__all__ = [
    "SyntheticEnterprise",
    "background_noise",
    "make_event",
    "write_jsonl",
]
