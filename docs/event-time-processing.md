# Event-Time Processing

Security telemetry does not arrive in order, on time, or exactly once. ARIADNE's
position is that a detection's verdict must depend on *what happened*, not on the
accidents of how its evidence was delivered. This document explains the two
clocks, the watermark, idempotent ingestion, and why a streaming admission layer
in front of a deterministic batch core converges on the same answer.

## Two clocks: event-time vs processing-time

`src/ariadne/events/schema.py::Event` carries two timestamps, kept deliberately
distinct:

- **`event_time`** — when the thing happened, according to the originating
  system. This is the *only* clock detections reason about. All windowing and
  sequencing in `match_sequence` is event-time semantics.
- **`observed_time`** — when ARIADNE first saw the event.

The gap is *lateness*, exposed as `Event.lateness_seconds`. A large gap is what
"the event arrived late" means. Both timestamps are coerced to timezone-aware UTC
on validation (`_ensure_utc`); naive datetimes are interpreted as UTC rather than
rejected, because recorded telemetry is routinely naive and a total order requires
comparable instants.

`event_time` drives correctness; `observed_time` drives only the one decision the
streaming layer must make — *is this event still admissible?*

## Watermarks

`src/ariadne/engines/windows.py::WatermarkTracker` is ARIADNE's estimate of how
far event-time has progressed:

```
watermark = max(event_time seen) - allowed_lateness
```

`observe(event)` advances `max_event_time`; `is_too_late(event)` returns `True`
when the event's own `event_time` is strictly below the current watermark:

```
def is_too_late(event):
    return watermark is not None and event.event_time < watermark
```

`allowed_lateness` is the slack band. Anything inside it is admitted and folded
into the batch core; anything older is considered unrecoverably late — the window
it belonged to is assumed closed — and is dropped rather than allowed to
retroactively change a result. `StreamingEvaluator` (in
`engines/reference.py`) collects these in `dropped_late` so the loss is visible
rather than silent.

Crucially, **late-but-admissible events change the result the same way no matter
when they show up.** Admission only decides membership in the set the batch core
evaluates; once admitted, an event participates in the deterministic event-time
matching exactly as if it had always been there.

## Allowed lateness and too-late dropping

`StreamingEvaluator.ingest(event)` is the admission gate:

```
def ingest(event):
    if watermark.is_too_late(event):
        dropped_late.append(event); return False    # past the slack band
    admitted = buffer.admit(event)                   # idempotent
    watermark.observe(event)                         # advance on admitted progress
    return admitted
```

A wider `allowed_lateness` tolerates more out-of-order delivery at the cost of
holding windows open longer; a narrower band closes faster but risks dropping a
genuinely late causal event. The default is 5 minutes.

## Idempotent ingestion

The streaming path must be idempotent: replaying the same event — a duplicate, a
reconnecting collector re-sending its buffer — must not change state.
`src/ariadne/engines/state.py::JoinBuffer` enforces this by keying admitted
events on `event.dedup_key` (the `event_id`); a second copy with the same key is a
no-op (`admit` returns `False`). The buffer holds events in arbitrary arrival
order; canonical ordering happens at read time (`ordered()` →
`canonical_order`), which is precisely what lets the streaming and batch paths
read the same sequence.

`Event` equality and hashing are by `event_id`, so events also deduplicate
cleanly in sets. For collectors that reconnect and re-emit a window under *fresh*
ids, `Event.content_fingerprint()` hashes the content (type, time, actor, device,
attributes) ignoring `event_id`, and `deduplicate(strategy="fingerprint")`
collapses those true duplicates too.

## Why streaming admission + deterministic batch core converge

`StreamingEvaluator.result()` is one line:

```
return self.engine.evaluate(self.buffer.ordered(), self.ir)
```

The streaming layer's entire job is to decide *which* events are admissible; it
never evaluates the rule itself. The admitted set is handed to the same
`ReferenceEngine` that the batch path uses, which re-canonicalizes and
re-deduplicates before matching. Therefore:

> The streaming answer is exactly the batch answer over the events that were
> admissible.

There is no separate streaming semantics to keep in sync, and no class of bug
where the live detector and the offline replay disagree. This equivalence is the
load-bearing design choice; everything about watermarks and buffers exists only to
make the *admissible set* well-defined under adversarial delivery.

## The perturbations, and the mutators that model them

Each real-world delivery hazard has a deterministic, seeded mutator in
`src/ariadne/replay/mutation.py`, and each is the perturbation a correct detection
must be invariant to (or, for the destructive ones, the loss it must be honest
about):

| Hazard | Mutator | Invariant expected |
|---|---|---|
| Out-of-order arrival | `shuffle` | verdict unchanged (canonical order erases it) |
| True duplicates (same id) | `duplicate` | verdict unchanged (dedup by `event_id`) |
| Late arrival | `with_lateness` | verdict unchanged (sets `observed_time` only) |
| Source clock skew | `clock_skew` | unchanged within window slack |
| Collector reconnect | `reconnect` | unchanged (re-emits ids, then shuffles) |
| A source going dark | `drop_type` | *destructive* — verdict may change, by design |
| A field unclassified | `drop_field` | *destructive* — probes what telemetry is needed |

The non-destructive mutators preserve the multiset of real observations — they
change how events arrive, not what happened. `with_lateness` stamps a randomized
`observed_time` strictly after `event_time`, modelling late arrival without
altering when the event occurred. `clock_skew` shifts every event from one
`provenance.source` by a fixed offset, preserving intra-source spacing — a
robust detection tolerates this up to its window slack. `reconnect` re-emits a
slice of events with their original ids and then shuffles, which is the nastiest
benign case a streaming detector faces: reordering plus duplication at once.

## Durability checks tie it together

`src/ariadne/replay/metrics.py::durability_report` is where these become a
measured property of a firing. It computes a baseline (`engine.evaluate(events,
ir).case_ids`) and re-evaluates under each mutation, recording pass/fail by
whether the fired `case_ids` are *identical*:

```
check("Late events",         mutation.with_lateness(events, "12m", seed=7))
check("Duplicate events",    mutation.duplicate(events, 0.3, seed=8))
check("Collector reconnect", mutation.reconnect(events, 6, seed=9))
check("5-minute clock skew", mutation.clock_skew(events, source=dominant, skew="5m"))
check("Missing dns.query telemetry",          mutation.drop_type(events, "dns.query"))
check("Missing repository_sensitivity ...",   mutation.drop_field(events, "repository_sensitivity"))
```

The non-destructive cases and the two tolerable ARIADNE-specific cases (a small
clock skew, a dropped *optional* source) are expected to land in `passes`.
Dropping the classification field the count step depends on is expected to land
in `fails` — and *naming* that failure is the point of the panel, not hiding it.
The property suite (`tests/property/`) generalises this: across generated event
streams and shuffles, the engine's case set is invariant to non-destructive
mutation. The durability panel turns that guarantee into a per-case statement an
analyst can read.
