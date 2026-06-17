# Architecture

ARIADNE is a compiler. A detection is not a query string or a bag of
if-statements; it is a typed program that is lowered to a single intermediate
representation and then subjected to many passes — local evaluation, SIEM
translation, ASCII rendering, differential analysis, durability probing. The
pipeline below is the spine of the system, and every box names the module that
implements it and the type that crosses the boundary to the next box.

```
   collectors            normalization              rules
  ┌──────────┐          ┌──────────────┐        ┌──────────────┐
  │ osquery  │          │ normalize_   │        │  DSL          │
  │ auditd   │  raw     │  record()    │ Event  │  Detection    │
  │ Zeek     ├─ dicts ──▶ canonical_   ├────────▶  compile_     │
  │ GitHub   │          │  order()     │ stream │  detection()  │
  │ CloudTrail│         │ deduplicate()│        │      │        │
  │ identity │          └──────────────┘        │      ▼        │
  └──────────┘                                  │  DetectionIR  │
                                                └──────┬───────┘
                              ┌──────────────────┬─────┴──────┬─────────────┐
                              ▼                  ▼            ▼             ▼
                      ┌──────────────┐   ┌─────────────┐ ┌──────────┐ ┌──────────┐
                      │ ReferenceEng │   │ compilers/  │ │ render_  │ │ replay/  │
                      │ match_       │   │  eql spl    │ │  tree()  │ │ diff +   │
                      │  sequence()  │   │  kql ch     │ │          │ │ durability│
                      └──────┬───────┘   └─────────────┘ └──────────┘ └──────────┘
                             │ EvaluationResult / SequenceMatch
                             ▼
                      ┌──────────────┐
                      │ Investigator │  signals → hypotheses → evidence
                      │  investigate │  minimal-evidence, timeline, case
                      └──────┬───────┘
                             │ Case
                             ▼
                      ┌──────────────┐
                      │ replay/runner│  ScenarioRunner → ReplayReport
                      │ CLI / console│
                      └──────────────┘
```

## Stage 1 — Collectors

Collectors are the org's existing telemetry agents: osquery/EDR on the endpoint,
auditd, Zeek for network, the GitHub audit log, CloudTrail, the identity
provider. They are *outside* the deterministic core and are treated as a trust
boundary (see [threat-model.md](threat-model.md)): ARIADNE assumes the bytes a
collector emits faithfully represent what the source recorded, and reasons about
everything downstream of that assumption. In this repository the collector
adapters are stubs — `src/ariadne/collectors/` is a placeholder — because the
core's contract is the *normalized record*, not the wire format. A collector's
only job is to emit a mapping that `normalize_record` can validate.

## Stage 2 — Event Normalizer

`src/ariadne/events/schema.py` defines `Event`, the one record type the whole
system reasons about. It keeps a small, stable spine — `event_id`, `event_type`,
`event_time`, `observed_time`, and the structured roots `actor`, `device`,
`provenance` — and sweeps everything source-specific into a flat `attributes`
namespace. Field addressing is dotted and lives in exactly one function,
`resolve_field`: `actor.user_id` and `device.id` reach the spine, a bare
`repository_sensitivity` reaches `attributes`. Because the DSL, the engine, the
compilers, and the explanations all call `resolve_field`, they cannot disagree
about what a field name means.

`src/ariadne/events/normalization.py` makes streams *comparable*.
`normalize_record` validates raw dicts into `Event`s; `canonical_order` sorts by
`Event.sort_key()` — the `(event_time, event_id)` tuple — into the single total
order the engine reasons about; `deduplicate` drops idempotent copies keeping the
first in canonical order. `prepare(events)` is the engine's front door: it
canonicalizes and deduplicates in one step. This stage is what makes the rest of
the system order-invariant: every permutation of the same multiset of events
sorts to the same sequence, so evaluation cannot depend on arrival order.

The two timestamps are deliberately distinct. `event_time` is when the thing
happened according to the source; it is the only clock detections reason about.
`observed_time` is when ARIADNE first saw it; the gap is *lateness*. See
[event-time-processing.md](event-time-processing.md).

## Stage 3 — Detection DSL / IR compiler

The surface language (`src/ariadne/rules/dsl.py`) is a handful of frozen
dataclasses: `Event` matchers with chainable `.where(field__op=value)`
conditions, `Sequence`, `Count`, `Absence`, and the top-level `Detection`. It is
deliberately small; the difficulty is not syntax but giving each combinator
precise event-time semantics, and those live in the engine.

`src/ariadne/rules/compiler.py::compile_detection` is the front compiler pass. It
lowers the DSL into `src/ariadne/rules/ast.py` — the `DetectionIR` tree —
resolving duration strings (`"45m"`) to `timedelta`s via `src/ariadne/timeutil.py`,
flattening conditions into a uniform `PredicateIR` list, and tagging steps as
`EventStepIR` or `CountStepIR`. Predicate semantics are defined once in
`src/ariadne/rules/predicates.py` (a Django-flavoured operator vocabulary:
`in`, `not_in`, `gte`, `regex`, `exists`, …) and shared by every consumer.
`src/ariadne/rules/validation.py::lint` runs static checks on the IR (count
window wider than the sequence window, non-positive windows, unknown severity).

**Why the IR is the central artifact.** Keeping evaluation on the IR rather than
the DSL is the discipline that makes ARIADNE a compiler and not an ad-hoc
matcher: there is one canonical form, and everything downstream is a pass over
it. The reference engine walks it, the four SIEM compilers translate it,
`render_tree` draws it, and `diff_detections` aligns two of them. Adding a new
backend is one new walk; it never touches the DSL or the engine.

## Stage 4 — Stateful Sequence Engine

`src/ariadne/engines/reference.py::ReferenceEngine` is the deterministic ground
truth. `evaluate(events, detection)` calls `prepare`, partitions events into
**join groups** keyed by `detection.join_by` (typically the resolved actor and
the device), runs the sequence matcher on each group, and evaluates negative
exceptions to decide whether a positive match is a real alert or a suppressed
firing. It returns an `EvaluationResult` of `SequenceMatch`es; each match carries
its `SequenceAssignment`, a deterministic `case_id`, and `suppressed_by`.

The matcher itself is `src/ariadne/engines/sequence.py::match_sequence`: a
**greedy earliest-match** algorithm. For each step it takes the earliest events
satisfying the step after the previous step's anchor, respecting per-step count
windows (`src/ariadne/engines/windows.py::earliest_count_window`) and the overall
sequence window. Earliest-match minimizes chain end time, which makes it optimal
for the only question that matters — "does an admissible assignment exist within
the window?" — and, on canonically sorted input, fully deterministic. The exact
semantics and their limits are in [detection-semantics.md](detection-semantics.md).

`StreamingEvaluator` wraps the same core behind a watermark
(`src/ariadne/engines/windows.py::WatermarkTracker`) and an idempotent
`JoinBuffer` (`src/ariadne/engines/state.py`). Events are `ingest`-ed in arrival
order; duplicates are dropped, too-late events rejected, and `result()` runs the
batch core over the admitted set — so the streaming answer is exactly the batch
answer over the admissible events.

## Stage 5 — Investigation Engine

`src/ariadne/investigation/investigator.py::Investigator.investigate` turns a
firing into a `Case` (`investigation/case.py`). It holds no opinions of its own;
it arranges what the engine and an *explicit* hypothesis model produce:

- `signals.py::compute_signals` derives named signals from the actor-scoped event
  slice (e.g. `bulk_restricted_clone`, `endpoint_telemetry_stopped`).
- `hypotheses.py::evaluate_hypotheses` scores competing explanations (H1–H6) with
  a transparent additive model normalized by softmax — no opaque score, no LLM.
- `evidence.py` holds four registers: supporting, contradictory, missing, neutral.
- `minimal.py::minimal_decisive_evidence` re-runs the real engine to find a
  1-minimal event subset that still fires.
- `timeline.py` reconstructs the ordered event thread and annotates telemetry
  gaps (selective blinding).
- `explanations.py::explain_match` emits one plain sentence per rule condition.

The crossing type out of this stage is `Case`, which renders to the analyst text
block and to the FastAPI/HTMX console panels.

## Stage 6 — Replay / Regression Lab

`src/ariadne/replay/` is where detections are stress-tested.
`runner.py::ScenarioRunner` replays a recorded `Scenario` (events plus a
manifest) through a pack and produces a `ReplayReport` with honest latency.
`mutation.py` applies deterministic, seeded, adversarial perturbations
(`shuffle`, `duplicate`, `with_lateness`, `clock_skew`, `reconnect`, and the
destructive `drop_type`/`drop_field`). `metrics.py::durability_report`
re-evaluates under each mutation and records whether the fired case set is
unchanged; `field_coverage` measures how much telemetry carries each referenced
field. `differential.py::diff_detections` compares two rule versions against one
incident and, on a regression, diagnoses the cause — a newly required field the
telemetry lacks, a raised count threshold, a narrowed window — rather than just
reporting that v2 went silent.

## Data backends

The pure-Python core has no database dependency; it runs on
`pydantic`, `typer`, `structlog`, and `networkx` alone (`pyproject.toml`).
Backends are optional and plug in at well-defined seams:

- **ClickHouse** is the high-volume execution path named in the diagram. The
  `clickhouse` compiler lowers the IR to `windowFunnel` / `countIf` SQL, so a
  detection authored once can run at scale where the funnel and count semantics
  map most faithfully (`compilers/clickhouse.py`).
- **DuckDB / Polars** (the `data` extra) back local analytics over event files
  without standing up a server.
- **MinIO / object storage** is where the immutable evidence bytes live;
  `Provenance.raw_ref` (`events/schema.py`) and `EvidenceObject.source_ref`
  (`events/provenance.py`) point at those objects so every conclusion walks back
  to bytes.
- **Postgres** is a natural home for case state in a deployment, though the
  reference implementation keeps cases in memory.

The contract in every case is the same: the IR and the `Event` model are the
fixed interface, and a backend is a translation target, never a place where
detection semantics are redefined. The reference engine remains the ground truth
against which any backend is checked (`tests/differential/`).
