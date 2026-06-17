# Contributing to ARIADNE

Thanks for your interest. ARIADNE's value is its correctness guarantees, so the
contribution bar is mostly about *tests*: a new detection, engine change, or
compiler is only done when the properties still hold.

## Development setup

```bash
uv venv
uv pip install -e ".[test,ui]"
uv run pytest -q
```

The full suite (unit, property, differential, regression, integration) runs in a
few seconds. The property tests use [Hypothesis](https://hypothesis.readthedocs.io)
and the integration tests skip automatically if the `ui` extra is absent.

## What "done" means

Depending on what you touch:

- **A new detection** lands in `rules/<pack>/` as a Python module exposing a
  `DETECTIONS` list. It must lint clean (`ariadne rules validate rules`) and, if it
  is meant to fire on a scenario, have a regression test asserting it does. Add
  MITRE ATT&CK technique ids to `tags`.

- **An engine change** must keep the determinism properties green
  (`tests/property/test_determinism.py`) and the documented semantics in
  [docs/detection-semantics.md](docs/detection-semantics.md) accurate. If you
  change semantics, update that document in the same PR.

- **A new SIEM compiler** registers in `ariadne.compilers.COMPILERS` and passes
  the differential fidelity tests (every event type and count threshold preserved).
  Annotate, do not silently drop, anything the dialect cannot express.

- **A new collector** lives in `ariadne.collectors`, returns normalized `Event`
  objects, and has a unit test mapping a representative source record.

- **A new scenario** is a seeded builder (`scenarios/<name>/build.py`) plus the
  generated `events.jsonl` and `scenario.json`. CI regenerates and diffs them, so
  the builder must be deterministic.

## Style

Match the surrounding code: precise, dry docstrings that explain *why*, modern
typed Python (3.11+), no dead abstractions. `ruff` config lives in
`pyproject.toml`. Keep the core pure-Python and dependency-light; heavy backends
stay behind optional extras.

## A note on the model

There is intentionally no LLM in scoring or factual conclusions. Contributions
that put a language model on the decision path will be declined; one behind an
optional, clearly-labelled summary interface that never affects scoring is welcome.

## Commit and PR hygiene

Small, focused commits with messages that explain the change. PRs should describe
what property or behaviour they preserve or add, and include the test that proves
it.
