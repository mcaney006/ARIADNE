# ARIADNE

**A deterministic insider-risk detection compiler and forensic replay engine.**

ARIADNE is a Python framework for defining, compiling, replaying, and testing
identity-centric behavioural detections across endpoint, cloud, network, and
developer telemetry. Unlike a rule repository, ARIADNE treats detections as
**stateful programs**. It tests them against duplicate, delayed, missing, and
out-of-order events, reconstructs the *minimal* evidence responsible for an
alert, and compares detection behaviour across rule versions and query backends.

Most security repositories contain rules. ARIADNE proves the rules are correct.

```bash
uv pip install -e ".[test,ui]"     # or: pipx install ariadne-ir
ariadne replay scenarios/departing_engineer --explain
```

---

## The idea in one screen

An engineer preparing to leave clones 19 restricted repositories in 11 minutes,
builds an encrypted archive, copies it to a USB volume, stops the endpoint
collector, and deletes their shell history — with no change ticket. Every action
is individually legitimate. ARIADNE joins them across identities, devices,
sessions, repositories, files, processes, and cloud events, and produces a case:

```text
CASE ARI-2026-7579
Detection: ARI-IR-0042@v1 — Restricted repository collection followed by data staging
Risk: 99 / 100
Confidence: High

Primary hypothesis:
  Malicious insider collection (p=0.99)
Competing hypothesis:
  Authorized migration (p=0.00)

Supporting evidence:
  8 github.repository.clone events within 4m16s  [E1001 … E1008]
  Encrypted archive created using gpg            [E1020]
  Data staged to removable_media                 [E1021]
  Endpoint telemetry stopped                     [E1022]
  First-ever access to restricted repositories   [E1001 … E1019]
  New access token created shortly before        [E1000]
  Shell history deleted                          [E1023]

Contradictory evidence:
  Activity originated from an enrolled corporate device
  User has legitimate engineering access

Missing evidence:
  No change-management approval, change ticket, DLP classification result

Minimal decisive evidence:
  E1001, E1002, E1003, E1004, E1005, E1006, E1007, E1008, E1020, E1021, E1022

Detection durability:
  passes: Late events, Duplicate events, Collector reconnect, 5-minute clock skew, Missing DNS
  FAILS:  Missing repository_sensitivity classification
```

The **minimal decisive evidence** is the smallest set of events that still fires
the detection — computed by re-running the engine and proving no event can be
removed. It is how a reviewer sees that the system understands its own logic
instead of emitting a mysterious score.

---

## Detection time travel

Replay an incident through the current pack:

```text
$ ariadne replay scenarios/departing_engineer
Scenario: departing-engineer
Events processed: 625
Detections triggered: 1
Behavior chains matched: 1
Case opened: ARI-2026-7579
Detection latency: 0.02 seconds
```

Then ask what a rule change did to it:

```text
$ ariadne diff rules/insider_risk/repository_collection.py \
               rules/insider_risk/_repository_collection_v2.py \
               scenarios/departing_engineer

DETECTION REGRESSION FOUND

Rule:
  ARI-IR-0042

Version 1:   Triggered (supporting events: 11)
Version 2:   Did not trigger

Cause:
  Version 2 requires file_sensitivity on github.repository.clone;
  94.1% of those events lacked the classification telemetry

Impact:
  False-negative introduced

Recommended correction:
  Permit an alternate signal (e.g. repository sensitivity) to satisfy the
  file_sensitivity condition when per-event classification is unavailable
```

That is the moment a home lab starts looking like something a security
engineering team would adopt: the framework didn't just run the rules, it
explained *why* a well-meaning edit silently broke one.

---

## The detection language

Detections are typed Python objects, not YAML. The surface DSL lowers to an
inspectable intermediate representation that every backend consumes.

```python
from ariadne.rules import Detection, Sequence, Event, Count, Absence

departing_engineer = Detection(
    id="ARI-IR-0042",
    title="Restricted repository collection followed by data staging",
    severity="critical",
    join_by=("actor.user_id", "device.id"),
    sequence=Sequence(
        within="45m",
        steps=[
            Count(
                Event("github.repository.clone").where(
                    repository_sensitivity="restricted",
                    access_is_first_seen=True,
                ),
                at_least=8, within="15m",
            ),
            Event("process.execution").where(process_name__in={"zip", "7z", "tar", "gpg"}),
            Event("filesystem.write").where(destination_type__in={"removable_media", "cloud_sync_folder"}),
            Event("security.telemetry_state").where(state__in={"stopped", "disabled", "degraded"}),
        ],
    ),
    exceptions=[
        Absence(Event("change_management.approval").where(approval_status="approved"), within="24h"),
    ],
)
```

```text
$ ariadne rules show rules/insider_risk/repository_collection.py
Detection ARI-IR-0042  (v1, critical)
  ├── Title: Restricted repository collection followed by data staging
  ├── Join: actor.user_id, device.id
  ├── Window: 45m
  ├── Count: github.repository.clone
  │     repository_sensitivity = 'restricted'
  │     access_is_first_seen = True
  │     threshold ≥ 8 within 15m
  ├── FollowedBy: process.execution where process_name in {'7z', 'gpg', 'tar', 'zip'}
  ├── FollowedBy: filesystem.write where destination_type in {'cloud_sync_folder', 'removable_media'}
  ├── FollowedBy: security.telemetry_state where state in {'degraded', 'disabled', 'stopped'}
  └── NegativeCondition: no change_management.approval where approval_status = 'approved' within 1d
```

That IR can be evaluated locally, **or compiled to a SIEM**:

```text
$ ariadne compile rules/insider_risk/repository_collection.py -t clickhouse
SELECT actor_user_id, device_id
FROM events
GROUP BY actor_user_id, device_id
HAVING
    windowFunnel(2700)(toUnixTimestamp(event_time),
        event_type = 'github.repository.clone' AND (repository_sensitivity = 'restricted' AND access_is_first_seen = true),
        event_type = 'process.execution'      AND (process_name in ('7z','gpg','tar','zip')),
        event_type = 'filesystem.write'        AND (destination_type in ('cloud_sync_folder','removable_media')),
        event_type = 'security.telemetry_state' AND (state in ('degraded','disabled','stopped'))
    ) = 4
    AND countIf(event_type = 'github.repository.clone' AND (repository_sensitivity = 'restricted' AND access_is_first_seen = true)) >= 8
    AND countIf(event_type = 'change_management.approval' AND (approval_status = 'approved')) = 0
```

Targets: `eql` · `spl` · `kql` · `clickhouse`. Each is honest about where a
dialect cannot express ARIADNE's exact event-time semantics and annotates the gap
rather than silently dropping it.

---

## Why this is more than a rule pack

### 1. It tests detection *semantics*

Security events arrive late, twice, with different timestamps, missing fields,
under multiple usernames, with clock drift, after an agent reconnects, in the
wrong order. ARIADNE must still behave deterministically. The core property,
checked with [Hypothesis](https://hypothesis.readthedocs.io) over hundreds of
synthesised streams:

```python
@given(event_streams())
def test_stable_under_shuffle_and_duplication(events):
    baseline = engine.evaluate(events, DETECTION).case_ids
    mutated  = duplicate(shuffle(events), fraction=0.4)
    assert engine.evaluate(mutated, DETECTION).case_ids == baseline
```

Canonical ordering (`(event_time, event_id)`) plus idempotent dedup make the
result a pure function of the event multiset and the rule. See
[docs/detection-semantics.md](docs/detection-semantics.md) and
[docs/event-time-processing.md](docs/event-time-processing.md).

### 2. It treats telemetry loss as evidence

When the endpoint agent stops while the network sensor still sees the same device
uploading data, that is not "the machine turned off" — it is selective blinding.
The timeline reconstructor surfaces the gap as a finding.

### 3. It performs identity resolution

One human is a GitHub login, a unix uid, an AWS principal, a VPN name, an email.
ARIADNE resolves them into one principal while keeping the confidence and
provenance of every link (graph connected-components; chain confidence multiplies,
corroboration combines by noisy-OR). See
[docs/identity-resolution.md](docs/identity-resolution.md).

### 4. It models competing explanations

Every case ranks explicit hypotheses — malicious insider, compromised
credentials, authorized migration, security testing, privileged abuse, broken
automation — with stated evidence weights, **no neural-network confidence fog**.
The same evidence model produces different conclusions across the three
scenarios; what differs is which signals are present.

### 5. It proves detections do not regress

`ariadne diff` aligns two rule versions against a recorded incident and explains
any regression, quantifying how much telemetry can actually satisfy a newly added
condition.

---

## The three flagship scenarios

| Scenario | Detection | ARIADNE concludes |
|---|---|---|
| `departing_engineer` | `ARI-IR-0042` | Malicious insider collection — and the authorized-migration mirror (same activity + approval) opens **no** case |
| `compromised_developer` | `ARI-CC-0017` | "More consistent with compromised credentials than deliberate insider activity" — because the enrolled device is silent |
| `privileged_admin` | `ARI-TT-0009` | Anomalous privileged abuse — while ignoring the admin's routine high-risk work |

Each scenario is regenerated deterministically from a seeded builder
(`scenarios/<name>/build.py`); CI asserts the events.jsonl is byte-stable.

---

## The investigation console

```bash
ariadne console      # http://127.0.0.1:8000  (needs the 'ui' extra)
```

FastAPI + HTMX + Tailwind. The case page has five panels — investigation thesis,
event thread (Person → Device → Process → File → Destination), why this fired,
alternative explanations, and detection durability. No 700-package frontend; the
spectacle belongs in the engine.

---

## Architecture

```text
Collectors → Event Normalizer → Detection DSL / IR compiler → Stateful Sequence
Engine → Investigation Engine → Replay / Regression Lab
```

The intermediate representation is the central artifact: one normalized form,
many passes (local evaluation, four SIEM exporters, the graph view, the
explanation builder). Full walkthrough in
[docs/architecture.md](docs/architecture.md).

| Layer | Module |
|---|---|
| Normalized events, provenance | `ariadne.events` |
| DSL → IR → linting | `ariadne.rules` |
| Event-time sequence engine | `ariadne.engines` |
| SIEM compilers | `ariadne.compilers` |
| Identity resolution | `ariadne.identity` |
| Investigation (hypotheses, minimal evidence, timeline) | `ariadne.investigation` |
| Replay, mutation, differential, durability | `ariadne.replay` |
| Console | `ariadne.api` |

---

## Benchmarks

Numbers are produced by a harness, not typed by hand
([benchmarks/](benchmarks/)). A reproducible small run:

```text
Dataset:  5,065 normalized events · 3 sequence detections   (Python 3.11)
Ingestion: ~19,000 events/second
P50 detection latency: 45 ms
P99 detection latency: 188 ms
Replay duration: 0.26 s
Peak memory: 42 MB
```

The reference engine is pure Python — the deterministic ground truth, not the
high-volume path (that is the ClickHouse compilation). CI runs the harness on
every push and uploads the result.

---

## Repository layout

```text
src/ariadne/        events · rules · engines · compilers · identity ·
                    investigation · replay · collectors · api · lab · cli
rules/              insider_risk · credential_compromise · telemetry_tampering
scenarios/          departing_engineer · compromised_developer · privileged_admin
tests/              unit · property · differential · regression · integration
benchmarks/         reproducible performance harness
lab/                docker + scenario_actions (real benign activity on decoys)
docs/               architecture · detection-semantics · event-time-processing ·
                    identity-resolution · privacy-and-ethics · threat-model ·
                    testing-behavioral-detections (the engineering paper)
```

## Stack

Python 3.11+ · Pydantic v2 · Typer · structlog · NetworkX · Hypothesis ·
pytest · FastAPI + Jinja + HTMX + Tailwind. Optional: DuckDB / ClickHouse /
Postgres / MinIO for high-volume and evidence storage.

```bash
uv pip install -e ".[test,ui]"
pytest -q
docker compose -f lab/docker/docker-compose.yml up   # optional backends
```

## On not adding an LLM

There is no language model in scoring or factual conclusions. The hard work is
correct event semantics, reliable correlation, explainability, replay, and
testing. An optional summary provider can sit behind an interface *after* all of
that works; it must never participate in scoring. See
[docs/privacy-and-ethics.md](docs/privacy-and-ethics.md).

## Authorized use

ARIADNE is a defensive tool for authorized insider-risk programs operating with
appropriate oversight. Its explainability and competing-hypotheses design exist
precisely to prevent opaque accusations. Read
[docs/privacy-and-ethics.md](docs/privacy-and-ethics.md),
[docs/threat-model.md](docs/threat-model.md), and [SECURITY.md](SECURITY.md).

## The engineering paper

[**Testing Behavioral Security Detections as Stateful Programs**](docs/testing-behavioral-detections.md)
— why string-matching rules fail, event time vs processing time, negative-event
detection, identity ambiguity, detection regressions, minimal-evidence
explanations, property-based and differential testing.

## License

[Apache 2.0](LICENSE).
