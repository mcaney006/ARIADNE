"""Deterministically (re)generate the privileged-administrator scenario.

Run from the repo root::

    python scenarios/privileged_admin/build.py

The incident: an administrator who legitimately performs high-risk actions every
day does something different. Outside the maintenance window, from a device never
seen before, they disable logging, mint a temporary privileged identity, pull a
restricted object, and then delete that identity to cover the trail. The rule
must ignore the routine high-risk work (seeded as benign admin noise) and fire
only on the anomalous, unapproved sequence.
"""

from __future__ import annotations

import json
from pathlib import Path

from ariadne.lab.synthetic import SyntheticEnterprise, make_event, write_jsonl

HERE = Path(__file__).parent
ACTOR = "admin_kim"
PERSONAL = "laptop-personal-kim"
ADMIN_HOST = "bastion-01"


def build() -> tuple[list, dict]:
    enterprise = SyntheticEnterprise(seed=99, employees=40)
    events = enterprise.background_noise(500, window_minutes=240)

    # Routine, approved high-risk admin work earlier in the day — must NOT alert.
    for index in range(12):
        events.append(
            make_event(f"A30{index:02d}", "iam.policy.change", 5 + index * 3,
                       source="cloudtrail", user_id=ACTOR, device_id=ADMIN_HOST,
                       device_enrolled=True, within_maintenance_window=True,
                       change="attach-policy")
        )

    chain: list = []
    chain.append(
        make_event("A4000", "identity.authentication", 150, source="okta",
                   user_id=ACTOR, device_id=PERSONAL, device_enrolled=False,
                   result="success", outside_maintenance_window=True,
                   device_is_first_seen=True)
    )
    chain.append(
        make_event("A4001", "security.telemetry_state", 156, source="cloudtrail",
                   user_id=ACTOR, device_id=PERSONAL, state="disabled",
                   telemetry_source="cloudtrail")
    )
    chain.append(
        make_event("A4002", "iam.user.create", 162, source="cloudtrail",
                   user_id=ACTOR, device_id=PERSONAL, privileged=True,
                   new_principal="svc-temp-break-glass")
    )
    chain.append(
        make_event("A4003", "aws.s3.get_object", 168, source="cloudtrail",
                   user_id=ACTOR, device_id=PERSONAL, bucket="ir-evidence",
                   key="cases/2026/restricted.zip", object_is_restricted=True)
    )
    chain.append(
        make_event("A4004", "iam.user.delete", 174, source="cloudtrail",
                   user_id=ACTOR, device_id=PERSONAL, privileged=True,
                   deleted_principal="svc-temp-break-glass")
    )

    events.extend(chain)

    manifest = {
        "id": "privileged-admin",
        "title": "Privileged administrator — off-hours logging disable and identity churn",
        "description": (
            "An administrator acts outside the maintenance window from an unseen device, "
            "disables logging, creates and deletes a temporary privileged identity, and "
            "retrieves restricted evidence."
        ),
        "detections": ["ARI-TT-0009"],
        "facts": {
            "outside_maintenance_window": True,
            "unseen_device": True,
            "contradictory": [
                "Actor holds legitimate standing administrator privileges",
            ],
            "missing_evidence": [
                "Approved maintenance ticket",
                "Break-glass justification record",
            ],
        },
        "expected": {
            "cases": 1,
            "detections_triggered": 1,
            "primary_hypothesis": "H5",
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
