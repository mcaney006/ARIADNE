# Testing Behavioral Security Detections as Stateful Programs

A behavioural security detection is a program. It reads a stream of events,
maintains state, and decides whether a sequence of facts crosses a line. We
nonetheless ship these programs the way nobody would ship any other program: as
a string of query language pasted into a console, versioned in a wiki, validated
by "it fired once in the demo." This article argues that behavioural detections
deserve the same treatment as the stateful programs they are — a typed source
language, a compiler, an intermediate representation, a deterministic reference
semantics, and a test suite that attacks the parts that actually break — and
describes how ARIADNE implements that treatment.

The thesis in one sentence: **the hard part of detection engineering is not
writing the rule, it is proving the rule still means what you think when the
telemetry is late, duplicated, missing, and out of order.**

## 1. Why string-matching rules fail

The dominant detection artifact is a query: a Sigma rule, an EQL sequence, an SPL
search. Three structural problems follow from treating the query as the source of
truth.

**The query is coupled to one engine's evaluation semantics.** "Sequence within
45 minutes" means subtly different things in Elastic EQL (`maxspan` over event
ingest order unless you sort), in Splunk (`transaction maxspan` over `_time`), and
in a hand-rolled correlation job. The same rule, ported across backends, drifts.
There is no neutral definition of what the rule *means* against which the ports
can be checked.

**The query has no testable notion of correctness.** A rule either returns rows
or it does not, on whatever data happens to be in the index today. There is no
fixture, no expected output, no property. "Does this still work?" is answered by
vibes.

**The query cannot reason about absence.** The most important fact in an insider
case is often the event that *should* be there and is not — the approval that was
never filed, the endpoint heartbeat that stopped. A search returns what exists; it
is structurally blind to what is missing.

ARIADNE's response is to demote the query. The source of truth is a typed Python
object (`ariadne.rules.dsl`) lowered to an intermediate representation
(`ariadne.rules.ast.DetectionIR`). The IR has a single reference semantics
(`ariadne.engines.reference.ReferenceEngine`). The SIEM queries become *outputs* —
compiler targets — not the artifact. A backend that cannot express a count
threshold inside a sequence annotates the gap; it does not get to redefine the
rule.

## 2. Event time versus processing time

Every event carries two clocks, and conflating them is the original sin of stream
detection.

- `event_time` — when the thing happened, per the originating system.
- `observed_time` — when the detector first saw it.

The gap between them is *lateness*. ARIADNE reasons exclusively about `event_time`.
Windowing, sequencing, and the count sub-windows are all event-time semantics. The
consequence is that a clone that happened at 22:04 but arrived at 22:30 is placed
at 22:04 in the chain, where it belongs, regardless of when it showed up.

This is not free. Reasoning about event-time means you must decide how long to
wait for stragglers before declaring a window closed. ARIADNE models this with a
watermark (`ariadne.engines.windows.WatermarkTracker`): the watermark is
`max(event_time seen) - allowed_lateness`, and an event whose own `event_time`
falls below the current watermark is *too late* — its window is assumed closed and
it is dropped rather than allowed to retroactively rewrite a result. Everything
inside the allowed-lateness band is admitted and folded into the deterministic
batch core, so a late-but-admissible event changes the verdict the same way no
matter when it arrives.

The streaming path and the batch path are deliberately the same engine. The
streaming evaluator (`StreamingEvaluator`) is a watermark and an idempotent buffer
in front of the batch core; calling `.result()` runs the batch evaluator over the
admitted set. This is what lets us claim — and test — that the live, out-of-order
answer equals the offline answer over the events that were admissible.

## 3. Duplicate and late telemetry, and why determinism is a property

Collectors reconnect and replay their backlog. Load balancers double-deliver.
Agents resend after an ACK is lost. A detector that changes its mind when an event
arrives twice is not a detector, it is a coin flip with extra steps.

ARIADNE makes determinism a *property of the evaluation function*, then tests that
property directly. Two mechanisms establish it:

1. **Canonical order.** Before matching, events are sorted by
   `(event_time, event_id)`. The `event_id` tiebreak makes the order total even
   when two events share a timestamp. Every permutation of the same multiset sorts
   to the same sequence, so the engine cannot depend on arrival order.

2. **Idempotent dedup.** Events are deduplicated on a key (`event_id` by default,
   or a content fingerprint for collectors that re-id their backlog), keeping the
   first occurrence *in canonical order* — not the first to physically arrive.

Together these make the result a pure function of the event multiset and the rule.
That is a falsifiable claim, so we falsify it. From
`tests/property/test_determinism.py`:

```python
@given(event_streams())
@settings(max_examples=200)
def test_stable_under_shuffle_and_duplication(events):
    baseline = ENGINE.evaluate(events, DETECTION).case_ids
    mutated  = mutation.duplicate(mutation.shuffle(events, seed=1), fraction=0.4, seed=2)
    assert ENGINE.evaluate(mutated, DETECTION).case_ids == baseline
```

`event_streams()` is a Hypothesis strategy that synthesises clone bursts of random
size and sensitivity, optional staging steps at random offsets, multiple actors,
and benign noise — firing and non-firing alike. The property holds across the
space, not on one lucky fixture. Companion properties assert invariance under
lateness (`with_lateness`), under collector reconnect (`reconnect`, which replays
a window of events and reshuffles), and idempotency of repeated evaluation.

The `case_id` that these properties compare is a SHA-256 over `(detection id,
version, join key, chain start time)` — stable across runs and orderings by
construction, which is exactly why it is a sound thing to assert equality on.

## 4. Negative-event detection

The strongest insider-risk signals are negative. ARIADNE has two kinds.

**Suppressing exceptions.** A detection carries `Absence` exceptions — authorising
events whose *presence* suppresses an otherwise-firing chain. The departing-engineer
rule fires only when there is no approved change ticket within 24 hours. This is
the difference between keyword matching and contextual detection: the identical
technical activity (bulk clone, archive, stage, telemetry stop), authorised, opens
no case. The regression test `test_authorized_migration_does_not_alert` adds an
approval to the malicious scenario and asserts silence. Crucially, exceptions are
scoped to the *actor*, not the device — an approval is bound to a person, not a
laptop — and the suppression window reaches backward from the chain start, because
authorisation precedes activity.

**Telemetry-loss-as-evidence.** When `security.telemetry_state` reports the
endpoint agent stopped while a network sensor keeps emitting for the same device,
that is not the machine powering off — it is selective blinding. The timeline
reconstructor (`ariadne.investigation.timeline`) detects this structurally: a stop
event on one source followed by live events from another becomes a flagged gap in
the event thread. A detector that only analyses events that exist cannot see this;
ARIADNE analyses the events that *should* exist and do not.

## 5. Identity ambiguity

One human appears as `mcaney`, `michael.caney`, an email, `github: mcaney006`, an
AWS principal `AROA...`, a unix `uid=501`, a VPN identity. A detection joined on a
raw username sees several unrelated actors; the chain never assembles.

ARIADNE resolves identities first (`ariadne.identity`). Identity atoms `(type,
value)` are nodes; links carrying confidence and source are edges; connected
components are principals. Confidence is explicit arithmetic, not a model: along a
chain of links it multiplies (a weak link anywhere weakens the inference), and
across independent corroborating links it combines by noisy-OR (more evidence only
ever raises confidence). Each resolved identity reports the best-path confidence to
its component's anchor, so a reviewer sees not just that two identifiers were
merged but how strongly and why. The detections then join on the resolved
principal, and the chain assembles across systems.

## 6. Detection regressions

Detections rot. Someone tightens a condition, adds a field requirement, raises a
threshold — each change locally reasonable, each capable of silently introducing a
false negative. The only honest way to know is to replay a known incident through
both versions and compare.

`ariadne diff` (`ariadne.replay.differential`) does exactly this. It evaluates both
rule versions against the same recorded incident, and when version 2 stops firing,
it diagnoses why: it aligns the two ASTs to find the constraint version 2 added,
then measures how much of the scenario's telemetry can actually satisfy that
constraint (`field_coverage`, scoped per event type). A regression caused by 94% of
clone events lacking a `file_sensitivity` classification is a fundamentally
different problem from a logic error, and the diff says which it is — with a
recommended correction (permit an alternate signal when the field is unavailable).
The cause analysis falls through a small ladder: a newly required, frequently
missing field; then a raised count threshold; then a narrowed window; then a
generic structural change. The regression test pins this end to end against the v2
rule shipped in the repo.

## 7. Minimal-evidence explanations

A detection that outputs "97% malicious" has told the analyst nothing they can
act on or contest. ARIADNE computes the **minimal decisive evidence set**: the
smallest subset of the contributing events that *still fires the detection*.

The algorithm (`ariadne.investigation.minimal`) is delta-debugging:
greedily drop events one at a time, keep each drop whenever the detection still
triggers, repeat until a full pass removes nothing. Critically it re-runs the real
engine on each candidate — the result is verified, not asserted. For the flagship
rule the minimal set is exactly the eight clones that satisfy the count threshold
plus the three single-event staging steps: eleven events out of hundreds. Two
properties pin it (`tests/property/test_minimal_evidence.py`): the minimal set
still fires, and it is 1-minimal (removing any single event breaks the firing).
That is a proof, in the literal sense, of what was load-bearing.

This is also the antidote to the "machine-learning fog" failure mode. The score
exists, but it is downstream of explicit, named indicators in an additive
hypothesis model (`ariadne.investigation.hypotheses`), and the case shows the
evidence for and against every competing explanation — malicious insider,
compromised credentials, authorised migration, security testing, privileged abuse,
broken automation. The same evidence model produces "insider" for one scenario and
"compromised credentials" for another; what differs is which signals are present,
not a different black box.

## 8. Property-based testing for detections

Unit tests pin known cases. They cannot pin the space of ways telemetry misbehaves.
Property-based testing can.

ARIADNE's properties fall into three groups:

- **Determinism** (§3): case ids invariant under shuffle, duplication, lateness,
  and reconnect; evaluation idempotent.
- **Minimality** (§7): the reported evidence set fires and is 1-minimal.
- **Durability** (`ariadne.replay.metrics.durability_report`): a firing's verdict
  is unchanged under each non-destructive mutation, and the *destructive* mutations
  reveal precisely which telemetry the detection cannot live without. Dropping the
  classification field the count step depends on is *expected* to break the firing
  — and naming that failure in the case's durability panel is the point, not a bug.

The durability panel is the most underrated output. It turns "is this rule robust?"
from an argument into a table:

```
Passes:  Late events · Duplicate events · 5-minute clock skew · Missing DNS · Collector reconnect
Fails:   Missing repository classification
```

Every line is a re-evaluation under a named perturbation, not a claim.

## 9. Differential testing across query backends

A rule that means one thing locally and another after compilation to a SIEM is
worse than no rule. ARIADNE compiles the IR to four dialects (EQL, SPL, KQL,
ClickHouse) and differential-tests the compilations for *structural fidelity*: we
cannot run Splunk and Sentinel in CI, but we can assert that every backend mentions
every event type the detection uses and preserves every count threshold
(`tests/differential/test_backend_fidelity.py`). A backend that silently dropped a
step or a threshold would diverge from the reference engine, and that is precisely
the class of bug this catches. Where a dialect genuinely cannot express ARIADNE's
semantics — a count window inside an EQL sequence, within-sequence negation in KQL
`scan` — the compiler emits an explicit annotation, so the divergence is documented
in the output rather than hidden.

## 10. What this buys you

A detection in ARIADNE is not a string you hope still works. It is a typed program
with a defined semantics, a minimal evidence proof for every firing, a durability
profile that names its telemetry dependencies, a regression check against recorded
incidents, and four compiled query forms that are tested to agree with the
reference. The dashboard is supporting material. The compiler, the event-time
engine, the identity correlation, the minimal-evidence explanations, and the
regression lab are the work — and they are the parts a security engineering team
can actually trust in production.

---

*Implementation: [ARIADNE](https://github.com/mcaney006/ariadne). The claims in
this article are each backed by code and tests in the repository; the section
references point at the modules and the suites that enforce them.*
