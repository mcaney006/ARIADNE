# Identity Resolution

Insider risk is about a human, not a log line. One person appears as a GitHub
login, a unix uid, an AWS principal, a VPN name, and an email; a chain of actions
that looks innocuous in any single system is the whole story when you know it is
one operator moving across all of them. ARIADNE resolves the fragments into a
*principal* while keeping the confidence and provenance of every link, so a
reviewer sees not only that two identifiers were merged but why and how strongly.

The implementation is `src/ariadne/identity/` — `graph.py`, `resolver.py`,
`confidence.py` — and it is small on purpose: identity correlation is the kind of
thing that drifts into a black box, and a black box has no place upstream of an
accusation.

## Atoms, links, assertions

The building blocks (`identity/graph.py`):

- **Identity atom** — a `(type, value)` pair such as `("github_user",
  "mcaney006")` or `("email", "m.caney@corp.example")`. Atoms are the nodes of
  the graph.
- **`IdentityAssertion`** — "source *S* observed identifier *(type, value)* with
  self-confidence *c*". An assertion is one system's claim that an identifier
  exists and is meaningful.
- **`IdentityLink`** — "atoms *left* and *right* are the same principal, with
  confidence *c*, per source *S*, because *reason*." A link is a weighted edge —
  the evidence that two atoms belong to one human.

## The graph and connected components

`build_graph(assertions, links)` constructs a `networkx.Graph`. Each asserted
atom becomes a node carrying its strongest self-confidence (`max` across
assertions) and the set of sources that reported it; each link becomes a weighted
edge. `IdentityResolver.resolve()` then treats each **connected component** as one
principal:

```
for component in nx.connected_components(graph):
    anchor = max(component, key=lambda atom:
                 (graph.nodes[atom]["confidence"], atom))
    ...
```

The **anchor** of a component is its highest-confidence atom — typically an
authoritative directory record (HR/IdP) — with the atom tuple itself as a
deterministic tiebreak. Every other identity's confidence is expressed *relative
to that anchor*. The principal's id is a stable digest of its sorted atoms
(`person-<sha6>`), so the same component always mints the same id.

## Confidence arithmetic

Two explicit rules (`identity/confidence.py`), each chosen so the number attached
to an identity is defensible rather than a vibe:

- **Along a chain of links, confidence multiplies** (`path_confidence` =
  product). A weak link anywhere weakens the whole inference. A → B at 0.9 and
  B → C at 0.8 gives A → C at 0.72.
- **Across independent evidence for the same equivalence, confidence combines by
  noisy-OR** (`merge_confidence` = `1 - Π(1 - vᵢ)`). More corroboration only ever
  raises confidence. Two independent 0.8 links yield 0.96, not 0.64.

### Best-path confidence to the anchor

Within a component, an identity's final confidence is its own self-confidence
scaled by the **strongest chain** connecting it to the anchor:

```
self_conf = graph.nodes[atom]["confidence"]
link_conf = _best_path_confidence(graph, atom, anchor)   # max product over paths
confidence = self_conf * link_conf
```

`_best_path_confidence` enumerates simple paths (cutoff 6) from the atom to the
anchor and returns the maximum product of edge confidences — the most credible way
to reach the trusted record. The anchor itself resolves to `1.0 * self_conf`. This
gives a principled gradient: an atom one strong hop from a directory record stays
near-certain; an atom reachable only through a chain of weak inferences is
correctly discounted.

## Auto-linking on shared unique values

Some attributes are globally unique by construction — the same email address in
two systems is strong evidence of one person. `_link_shared_unique_values` walks
the assertions, groups atoms of a `_GLOBALLY_UNIQUE_TYPES` type (currently
`{"email"}`) by value, and adds a confidence-`1.0` edge
(`source="shared-unique-value"`, `reason="identical email across sources"`)
between atoms that share a value. This is how a GitHub identity and an AWS
identity that both carry the same corporate email fall into one component without
anyone authoring an explicit link. The set is intentionally narrow — only types
the org knows to be unique should auto-link, since a false merge here pollutes
every downstream conclusion.

## A resolved principal

`Principal.to_dict()` is the analyst-facing shape. One human across GitHub, unix,
AWS, VPN, and a directory record resolves to:

```json
{
  "principal_id": "person-9f2a14",
  "identities": [
    { "type": "email",       "value": "m.caney@corp.example", "confidence": 1.0,    "source": "okta" },
    { "type": "github_user", "value": "mcaney006",            "confidence": 0.98,   "source": "github_audit" },
    { "type": "unix_uid",    "value": "1007",                 "confidence": 0.9216, "source": "osquery" },
    { "type": "aws_principal","value": "AIDA...MCANEY",        "confidence": 0.96,   "source": "cloudtrail" },
    { "type": "vpn_user",    "value": "mcaney",               "confidence": 0.85,   "source": "vpn" }
  ]
}
```

The anchor is the directory email (confidence `1.0`); each other identity's number
is its self-confidence times the best chain back to that anchor. A reviewer can
read the list top to bottom and see which identifiers are certain and which are
inferred, with the source of each.

## Why this matters for insider risk

The detections in `rules/` join on `actor.user_id` (and often `device.id`). That
field is only meaningful if "the same actor" means *the same human*, not the same
GitHub login. Without resolution, a person who mints a token as their GitHub
identity, authenticates as an AWS principal, and stages data under a unix uid
splinters into three actors and no chain ever forms — exactly the evasion an
insider gets for free by operating across systems (see
[threat-model.md](threat-model.md), identity fragmentation). Identity-centric
correlation is what lets `ARI-CC-0017` (token → unusual-infra auth → enumerate →
cloud pull) and `ARI-IR-0042` (clone burst → archive → stage → telemetry stop)
see one operator instead of five disconnected events. The `Actor` model reflects
this directly: `user_id` is whatever local identifier a source knew, while
`principal_id` is the *resolved* identity — the output of this module — which
normalization can stamp onto raw telemetry so the engine joins on the human.
