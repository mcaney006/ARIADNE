"""Deterministically (re)generate the compromised-developer scenario.

Run from the repo root::

    python scenarios/compromised_developer/build.py

The incident: a developer's credential is stolen. A new token is minted, used to
authenticate from unfamiliar infrastructure, enumerate repositories, and pull a
restricted object out of S3 — all while the developer's enrolled laptop shows no
activity at all. ARIADNE should prefer "compromised credentials" over "malicious
insider" precisely because the human's endpoint is silent.
"""

from __future__ import annotations

import json
from pathlib import Path

from ariadne.lab.synthetic import SyntheticEnterprise, make_event, write_jsonl

HERE = Path(__file__).parent
ACTOR = "rlee"
VPS = "vps-203-0-113-9"


def build() -> tuple[list, dict]:
    enterprise = SyntheticEnterprise(seed=7, employees=40)
    events = enterprise.background_noise(500, window_minutes=240)

    chain: list = []
    chain.append(
        make_event("C2000", "github.token.create", 8, source="github_audit",
                   user_id=ACTOR, token_name="ci-deploy", scopes="repo")
    )
    chain.append(
        make_event("C2001", "identity.authentication", 12, source="okta",
                   user_id=ACTOR, device_id=VPS, device_enrolled=False,
                   result="success", infrastructure_is_unusual=True,
                   asn="AS14061", geo="unexpected")
    )
    for index in range(9):
        chain.append(
            make_event(f"C{2002 + index}", "github.repository.clone", 14 + index * 0.8,
                       source="github_audit", user_id=ACTOR, device_id=VPS,
                       device_enrolled=False, repository=f"restricted/svc-{index:02d}",
                       repository_sensitivity="restricted", access_is_first_seen=True)
        )
    chain.append(
        make_event("C2020", "aws.s3.get_object", 24, source="cloudtrail",
                   user_id=ACTOR, bucket="acme-secrets", key="prod/credentials.json",
                   object_is_restricted=True)
    )

    events.extend(chain)

    manifest = {
        "id": "compromised-developer",
        "title": "Compromised developer — token abuse from unusual infrastructure",
        "description": (
            "A stolen credential is used from unfamiliar infrastructure to enumerate "
            "repositories and pull restricted cloud objects, with no endpoint activity."
        ),
        "detections": ["ARI-CC-0017"],
        "facts": {
            "auth_from_unusual_infra": True,
            "no_endpoint_activity": True,
            "contradictory": [
                "Valid credentials were used (no brute force observed)",
            ],
            "missing_evidence": [
                "Endpoint telemetry from the employee's enrolled device",
                "MFA challenge result",
            ],
        },
        "expected": {
            "cases": 1,
            "detections_triggered": 1,
            "primary_hypothesis": "H2",
        },
    }
    return events, manifest


def main() -> None:
    events, manifest = build()
    count = write_jsonl(events, HERE / "events.jsonl")
    (HERE / "scenario.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {count} events to {HERE / 'events.jsonl'}")


if __name__ == "__main__":
    main()
