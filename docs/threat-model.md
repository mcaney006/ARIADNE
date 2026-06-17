# Threat Model

This document states what ARIADNE is designed to detect, what an adversary can do
to evade it, what is explicitly out of scope, and where the trust boundaries lie.
It is grounded in the rule pack (`rules/`), the engine
(`src/ariadne/engines/`), and the replay lab (`src/ariadne/replay/`).

## What ARIADNE detects

ARIADNE recognises multi-step *behavioural* sequences, scoped to a resolved human,
that are individually plausible but collectively anomalous. The shipped rules
cover four insider-risk archetypes:

| Detection | Archetype | Shape |
|---|---|---|
| `ARI-IR-0042` | Insider collection | Burst of first-seen restricted clones → archive → stage to removable/cloud-sync → telemetry stop, in 45m, unapproved |
| `ARI-CC-0017` | Credential compromise | New token → auth from unusual infra → clone enumeration → restricted S3 pull, in 30m |
| `ARI-TT-0009` | Privileged abuse + telemetry tampering | Off-hours auth from unseen device → disable audit logging → create privileged identity → pull restricted → delete identity, in 60m, unapproved |

The unifying idea: administrators and engineers do high-risk things all day, so
volume alone is useless. The anomalous *sequence* — and, for the contextual rules,
the *absence of authorization* — is the signal.

## Adversary capabilities relevant to evasion

ARIADNE's design assumes a motivated adversary who understands they are being
logged and shapes their delivery and footprint to defeat naive detection. The
engine and lab are built around the specific evasions below.

### Late, duplicate, and out-of-order events

A pipeline (benignly or adversarially) can deliver events reordered, duplicated,
or delayed. ARIADNE neutralises this *structurally*: after `prepare` the engine
reasons only over the canonical `(event_time, event_id)` order and a deduplicated
multiset, so arrival order and true duplicates cannot change a verdict (see
[detection-semantics.md](detection-semantics.md) and
[event-time-processing.md](event-time-processing.md)). The mutators `shuffle`,
`duplicate`, `with_lateness`, and `reconnect` in `replay/mutation.py` are the
adversary's delivery games made into seeded, reproducible tests, and
`durability_report` proves a firing survives them. An adversary therefore cannot
evade by manipulating *when or how often* evidence arrives — only by changing
*what happened*.

### Telemetry tampering — and treating loss as evidence

The strongest evasion is to stop the sensor. A real attacker disables the endpoint
agent or audit logging before staging data. ARIADNE does not pretend the gap is
nothing:

- `ARI-IR-0042` includes `security.telemetry_state … state in {stopped, disabled,
  degraded}` as a *required step* — the act of going dark is part of the pattern,
  not a hole in it. `ARI-TT-0009` requires disabling `audit`/`logging`/`cloudtrail`.
- `investigation/timeline.py::_detect_telemetry_gaps` surfaces **selective
  blinding**: when one source reports a stop while a `_LIVE_SOURCE`
  (`zeek`, `network`, `cloudtrail`, `github_audit`, `okta`) keeps emitting for the
  same device, the timeline annotates a `telemetry.gap` entry. An endpoint that
  "turns off" while the network sensor still sees it uploading is not a dead
  machine — it is evidence.
- The destructive mutator `drop_type` and `durability_report` quantify exactly
  which sources a detection cannot live without, so blinding a source is a known,
  named weakness rather than a silent false negative.

### Identity fragmentation

Operating across systems splinters one human into many actors, so no chain forms.
ARIADNE counters this with identity resolution
([identity-resolution.md](identity-resolution.md)): the GitHub login, AWS
principal, unix uid, and VPN name resolve to one principal, and detections join on
the resolved actor. The credential-compromise rule explicitly turns the *missing*
endpoint of the real human (their enrolled laptop shows nothing) into a
distinguishing signal rather than a blind spot.

### Classification gaps — the v2 regression story

A subtler failure is self-inflicted: a well-meaning rule edit that depends on
telemetry the org does not reliably produce.
`rules/insider_risk/_repository_collection_v2.py` tightened the count step to
require per-file `file_sensitivity="restricted"` instead of repository-level
`repository_sensitivity`. It is more precise on paper, but most clone events never
receive file-level classification, so the rule *silently stops firing*.
`replay/differential.py::diff_detections` exists to catch exactly this: it aligns
the two ASTs, finds the added constraint, and uses `field_coverage` to report
"version 2 requires `file_sensitivity`; N% of those events lacked the
classification telemetry — false negative introduced." An adversary who knows a
detection depends on a flaky classifier can exploit the gap; the diff makes the
gap measurable and the regression diagnosable, distinguishing a coverage problem
from a logic error.

### Clock skew

Sources drift. `clock_skew` shifts every event from one `provenance.source` by a
fixed offset while preserving intra-source spacing; a robust detection tolerates
this up to its window slack, and `durability_report` checks a 5-minute skew on the
dominant source. An adversary cannot reliably evade by exploiting modest drift,
because the windows carry slack and the skew is bounded by what a real clock does;
a *large* deliberate offset would shift an event's `event_time` and is, in effect,
telemetry tampering, handled above.

## Out of scope and trust assumptions

ARIADNE draws a clear trust boundary and does not claim to defend across it:

- **Collectors are trusted.** ARIADNE assumes the bytes a collector emits
  faithfully represent what the source recorded. A compromised collector that
  *fabricates* plausible-but-false events, or that drops events while reporting
  health, is outside the model — that is an endpoint/agent-integrity problem, not
  a detection-logic problem. `Provenance.confidence` lets a deployment down-weight
  a less-trusted source, but ARIADNE cannot detect a perfectly forged record.
- **The normalizer is trusted.** Field resolution and canonicalization are assumed
  correct; a detection's meaning is only as sound as `resolve_field`.
- **The engine is deterministic ground truth.** Everything else — the SIEM
  compilers, the streaming evaluator, any backend — is *measured against* the
  reference engine (`tests/differential/`). ARIADNE does not assume a third-party
  SIEM reproduces its exact semantics; the compilers annotate where a dialect
  cannot (count thresholds, within-sequence negation), and the local engine
  remains authoritative.
- **Not an access-control or prevention system.** ARIADNE detects and explains; it
  does not block, quarantine, or enforce policy. Consequences are a human decision.
- **No content inspection.** The model reasons over structured metadata, not file
  contents or message bodies; an exfiltration that produces no recognisable
  metadata footprint is not visible to it.

## MITRE ATT&CK mapping

The rule tags map detections to ATT&CK techniques (grep `rules/` for the `T####`
tags):

| Technique | ID | Detection(s) |
|---|---|---|
| Exfiltration Over Web Service | `T1567` | `ARI-IR-0042` |
| Archive Collected Data | `T1560` | `ARI-IR-0042` |
| Valid Accounts | `T1078` | `ARI-CC-0017`, `ARI-TT-0009` |
| Valid Accounts: Cloud Accounts | `T1078.004` | `ARI-TT-0009` |
| Data from Cloud Storage | `T1530` | `ARI-CC-0017` |
| Impair Defenses | `T1562` | `ARI-TT-0009` |

The mapping is a property of the rule, carried as `Detection.tags` through to the
IR, so it travels with the detection into every compiled backend and every case.
