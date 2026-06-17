# Detection Semantics

This document defines, precisely, what it means for a detection to *match*. The
authority is `src/ariadne/engines/reference.py` and
`src/ariadne/engines/sequence.py`; the prose here describes what that code does
and is explicit about where it stops.

A detection (`DetectionIR`) is an ordered `SequenceIR` of steps, a `join_by`
tuple, an overall sequence window, and zero or more `AbsenceIR` exceptions.
Evaluation answers one question per join group: *does an admissible assignment of
events to steps exist within the window, and is it suppressed by an authorising
event?*

## Canonical order and determinism

Before any matching, `ReferenceEngine.evaluate` calls `prepare`, which
canonicalizes (`canonical_order`) and deduplicates the events. Canonical order is
the sort by `Event.sort_key()`:

```
sort_key = (event_time, event_id)
```

`event_time` is the primary key; `event_id` is the tiebreak that makes the order
*total* even when two events share an event-time. Two consequences follow and are
asserted by `tests/property/test_determinism.py`:

1. **Order-invariance.** Every permutation of the same multiset of events sorts to
   the same sequence, so the engine output cannot depend on arrival order.
2. **Dedup-invariance.** `deduplicate` keeps the first occurrence *in canonical
   order*, so the surviving copy does not depend on which physical copy arrived
   first.

Together: canonical order + dedup ⇒ the result is a pure function of the event
multiset and the rule. The `case_id` (a SHA-256 over detection id, version, join
key, and chain start time) is therefore stable across runs and across orderings.

## Join scoping

`_evaluate_prepared` partitions the prepared events into **join groups**, one per
distinct value of `_join_key(event, ir.join_by)` — the tuple of resolved
`join_by` fields. For `ARI-IR-0042` the join is `("actor.user_id", "device.id")`,
so each group is one person on one device. The sequence matcher runs
independently on each group; an alert is attributed to exactly one join group.
Events whose join fields resolve to `None` form their own group keyed on `None`
and are not silently merged with anyone else.

## Greedy earliest-match

`match_sequence(events, sequence)` walks the steps left to right against the
canonically ordered group, carrying three pieces of state:

- `cursor` — the index past the last consumed event (steps consume forward only),
- `anchor` — the event-time at which the previous step completed; the next step's
  events must be at or after it,
- `chain_start` — the event-time of the first matched event, against which the
  overall `within` is measured.

For an **event step** (`_match_event_step`) it returns the first event at or after
`anchor` that satisfies the matcher, provided it lands within
`chain_start + overall_within`. For a **count step** it collects all qualifying
candidates at or after `anchor` and hands them to `earliest_count_window`.

The choice is **greedy earliest**: each step takes the earliest events that
satisfy it. The completion time of a step is the event-time of its last assigned
event (`StepMatch.anchor` = `events[-1].event_time`).

### Why earliest-match is optimal here

The question the engine answers is existential, not optimization:

> Does *some* admissible assignment fit inside the window?

Earliest-match minimizes the end time of each step's contribution, and therefore
minimizes the end time of the whole chain. If the chain produced by always taking
the earliest admissible event still overflows the window, then *no* assignment
fits — any later choice ends no sooner. So greedy-earliest is a sound and complete
decision procedure for "an admissible assignment exists within the window,"
respecting step order. And because the input is canonically sorted, the events it
picks are a deterministic function of the multiset: the same events always yield
the same `SequenceAssignment`.

## Count steps

`Count(pattern, at_least=N, within=W)` (lowered to `CountStepIR`) is satisfied by
**at least N** qualifying events whose span fits inside the sub-window `W`.
`earliest_count_window` (in `engines/windows.py`) exploits the fact that, over a
sorted series, the tightest window covering `N` events is always a contiguous
slice:

```
for start in 0 .. n-N:
    window = candidates[start : start+N]
    if window[-1].event_time - window[0].event_time <= W:
        return window      # earliest admissible run of N
```

The **anchor** of a satisfied count step is the event-time of its `N`-th (last)
event — that is the moment the threshold is reached, and it is what the next step
must follow. The count step also re-checks the overall window: its last event
must not exceed `effective_start + overall_within`. `ARI-IR-0042`'s first step is
`Count(github.repository.clone … , at_least=8, within="15m")`: it fires when 8
qualifying clones occur inside any 15-minute slice, and the 8th clone anchors the
rest of the chain.

## The overall sequence window

`SequenceIR.within` (e.g. `45m`) bounds the entire chain. `chain_start` is fixed
by the first matched event; every subsequent step — event or count — is rejected
if it would push past `chain_start + within`. Note that the count sub-window `W`
and the sequence window are independent constraints; the lint check
`count-window-too-wide` warns when `W` exceeds the sequence window, since the
narrower one then dominates.

## Ordering on event-time

All ordering is **event-time** ordering with the `(event_time, event_id)`
tiebreak. A step's events must be at or after the previous step's anchor in
event-time, never in arrival/`observed_time`. This is why late, shuffled, or
duplicated arrivals cannot change the verdict: the engine never looks at arrival
order after `prepare`. `observed_time` matters only at the streaming admission
boundary (watermark), never inside `match_sequence`.

## Absence / negative exceptions

Exceptions are **authorising context**. After a positive `SequenceAssignment` is
found, `_evaluate_exceptions` checks each `AbsenceIR`: if an authorising event of
the absence's type and predicates is present, the firing is *suppressed* (added to
`suppressed_by`) rather than emitted as an alert. `SequenceMatch.triggered` is
`True` only when `suppressed_by` is empty.

Two scoping rules matter:

- **Time scope.** The authorising event must fall in
  `[assignment.start_time - absence.within, assignment.end_time]`. The window
  reaches *backward* from the chain start by `within`, because an approval ticket
  filed before the activity still authorises it.
- **Actor scope.** Suppression is scoped to the actor, not the device. When
  `actor.user_id` is part of the join, only authorising events for the same
  `actor.user_id` count — an approval ticket is bound to the person, not their
  laptop.

For `ARI-IR-0042`, the exception is `Absence(change_management.approval where
approval_status="approved", within="24h")`. Add an approved ticket for the same
actor and the identical technical chain stops alerting. This is the contextual
half of "contextual detection, not keyword matching."

## Worked example: ARI-IR-0042

```
Detection ARI-IR-0042  (v1, critical)
  ├── Join: actor.user_id, device.id
  ├── Window: 45m
  ├── Count: github.repository.clone
  │     repository_sensitivity = 'restricted'
  │     access_is_first_seen = True
  │     threshold ≥ 8 within 15m
  ├── FollowedBy: process.execution where process_name in {7z, gpg, tar, zip}
  ├── FollowedBy: filesystem.write where destination_type in {cloud_sync_folder, removable_media}
  ├── FollowedBy: security.telemetry_state where state in {degraded, disabled, stopped}
  └── NegativeCondition: no change_management.approval where approval_status = 'approved' within 24h
```

For one actor on one device:

1. Restricted, first-seen clones are gathered in canonical order; the earliest run
   of 8 spanning ≤ 15m is the count window. Its 8th clone anchors the chain;
   `chain_start` is the 1st clone's time.
2. The first `process.execution` matching an archive tool at or after the anchor
   and within `chain_start + 45m` is taken.
3. Then the first qualifying `filesystem.write`, then the first qualifying
   `security.telemetry_state`, each advancing the anchor and re-checking the 45m
   bound.
4. With all four steps assigned, the exception window
   `[chain_start - 24h, end]` is scanned for an approved ticket *for that actor*.
   None ⇒ alert; one ⇒ suppressed.

The departing-engineer scenario clones 19 restricted repos in 11 minutes, builds
an archive, copies to removable media, stops endpoint telemetry, and files no
approval — so the chain matches and is not suppressed.

## Known limitations (stated honestly)

- **One assignment per join group.** `match_sequence` returns at most one
  `SequenceAssignment` per group — the earliest. If the same actor/device
  performs two distinct qualifying chains, the engine reports the first, not both.
- **Greedy, not exhaustive search.** The matcher does not backtrack across step
  *predicate* interactions beyond the earliest-completion property. For the
  existential window question this is provably sufficient (earliest end time is a
  lower bound on every assignment's end time); but it is not a general
  constraint-satisfaction search, and a detection that required, say, the *same*
  attribute value to recur across non-adjacent steps would need a richer matcher.
- **Count windows are contiguous slices.** `earliest_count_window` assumes the
  tightest N-window is a contiguous slice of the sorted candidates, which is true
  for "N events within W" but would not generalise to non-monotonic constraints.
- **Exception actor scope is `actor.user_id`-specific.** Suppression only narrows
  by actor when `actor.user_id` is in `join_by`; a rule joined on something else
  evaluates exceptions across all events in the time window.

These are conscious trade-offs in favour of determinism and a decision procedure
that is easy to reason about, not oversights.
