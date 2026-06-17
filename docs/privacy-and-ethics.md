# Privacy and Ethics

ARIADNE is a defensive, authorized-use tool for insider-risk programs. It is built
to make a hard, sensitive judgement — *is this person's activity malicious?* —
auditable, contestable, and grounded in evidence rather than to automate
suspicion. This document states the intended use, the design choices that serve
it, the ways the tool could be misused, and the guardrails. It is part of the
codebase because the ethics are not an afterthought bolted onto the engine; they
are why the engine is shaped the way it is.

## What ARIADNE analyzes

ARIADNE reasons over **telemetry the organization already collects** for security
purposes — endpoint process and filesystem events, the GitHub audit log,
CloudTrail, network metadata, identity-provider logs. It does not introduce new
surveillance; it correlates existing logs. The normalized `Event` model
(`src/ariadne/events/schema.py`) keeps a deliberately small spine (who, what,
when, where, provenance) and does not require message bodies, file contents, or
keystroke capture to function. The flagship detection fires on the *shape* of an
incident — a burst of restricted clones, an archive, a stage to removable media, a
telemetry stop — not on reading anyone's files.

## Intended context: authorized programs with oversight

This is a tool for a sanctioned insider-risk program operating under HR and legal
oversight, with a defined scope, lawful basis, and review process. ARIADNE does
not decide consequences; it produces a `Case` (`investigation/case.py`) for a
human investigator. Every artifact in that case is designed to be handed to
someone who must justify a decision to HR, legal, and possibly the affected
employee.

## Explainability over an opaque score

The single most important ethical choice is the refusal to emit a mystery number.
A case is never "97% malicious" from a model nobody can inspect. Instead:

- **Minimal decisive evidence** (`investigation/minimal.py`) re-runs the *real
  engine* to find a 1-minimal subset of events from which no single event can be
  removed without the detection ceasing to fire. The case reports those event ids.
  An investigator can read the handful of records that were actually load-bearing
  rather than trust a verdict.
- **Per-condition explanation** (`investigation/explanations.py::explain_match`)
  emits one plain sentence per rule condition, naming the events that satisfied it.
- **Four evidence registers** (`investigation/evidence.py`): supporting,
  contradictory, missing, neutral. The contradictory and missing registers are not
  decoration — they are required output.

The point is that an accusation should be auditable line by line. A tool that
cannot explain itself cannot be used responsibly against a person's livelihood.

## Competing hypotheses: benign explanations first

`investigation/hypotheses.py` forces the consideration of innocent explanations
before alleging malice. The default hypothesis set (H1–H6) deliberately mixes
malicious and benign explanations for the *same* activity:

- H1 malicious insider collection,
- H2 **compromised developer credentials** (the person may be a victim, not a
  perpetrator),
- H3 **authorized migration**,
- H4 **security-team testing**,
- H5 privileged-administrator abuse,
- H6 **broken automation**.

Scoring is a transparent additive model normalized by softmax; every indicator
states its weight and whether it supports or contradicts. The investigator
explicitly surfaces a `leading_alternative` — the most relevant explanation of the
*opposite* class — so the case always shows the best competing story
(`_leading_alternative`). And the risk score is deflated when the leading
explanation is benign (`_risk_score` multiplies by `0.25` for non-malicious
primaries), so a likely-innocent case cannot present as high risk. Credential
compromise (H2) is a first-class hypothesis precisely so that "someone stole this
person's token" is weighed before "this person is a thief"; the
`ARI-CC-0017` detection and the `_thesis` override for H2 exist to keep that
distinction visible.

## Data minimization

The schema collects structured metadata, not content. Detections are authored
against fields like `repository_sensitivity`, `destination_type`, and
`process_name` — the minimum needed to recognise an exfiltration shape — and the
engine resolves only the fields a rule references. `field_coverage`
(`replay/metrics.py`) even measures how much of each referenced field the
telemetry carries, which doubles as a check that the program is not silently
depending on data it does not have. Less data in scope is both a privacy property
and a correctness property.

## Provenance and chain of custody

Every conclusion must trace back to bytes. `Provenance` (`events/schema.py`)
carries `source`, `collector`, and `raw_ref` — a pointer to the immutable evidence
object — alongside the collector's own `confidence`. `EvidenceObject`
(`events/provenance.py`) seals a SHA-256 digest at acquisition, supports `verify`
to re-hash supplied bytes against that digest, and appends an immutable
`CustodyEntry` on every `transfer`. This is what lets an investigation cite *where*
a fact came from and *who* has touched the artifact since — the difference between
an accusation and admissible evidence.

## The deliberate choice not to use an LLM in scoring

There is no language model anywhere in the detection or scoring path. The matching
is a deterministic event-time algorithm; the hypothesis model is explicit additive
weights and a softmax. This is a conscious trade of probabilistic sophistication
for explainability and reproducibility:

- The same incident always produces the same case (`case_id`, scores, minimal
  evidence) — auditable and challengeable.
- Every contribution to a verdict is a named indicator with a stated weight, not a
  latent activation.
- There is no prompt-injection or hallucination surface in the path that decides
  whether to flag a human.

For a tool whose output can end a career, "I can show you exactly why, and you can
reproduce it" is worth more than a marginally better but unexplainable score.

## Potential for misuse, and the guardrails

A tool that correlates an employee's activity across every system is, by its
nature, a surveillance capability, and it could be abused: deployed without
authorization, scoped to monitor disfavoured individuals, used to manufacture a
case, or run without the oversight that legitimizes it. ARIADNE does not and
cannot enforce an organization's governance, and this document does not pretend
otherwise. What the design *does* provide as guardrails:

- **No automated action.** ARIADNE produces a case for a human; it does not
  block, fire, or punish.
- **Mandatory contradictory and missing evidence**, so a case cannot present only
  the prosecution's view.
- **Benign hypotheses weighted first**, deflating risk when innocence is the more
  consistent explanation.
- **Full provenance**, so a fabricated or altered basis can be detected.
- **Determinism**, so a case can be independently reproduced and disputed.

These make *misuse harder to hide* and *honest use easier to defend*. They do not
substitute for a lawful basis, defined scope, proportionality, and HR/legal review
— those are organizational obligations, and ARIADNE should only be operated inside
them.
