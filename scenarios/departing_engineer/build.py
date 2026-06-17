"""Deterministically (re)generate the departing-engineer scenario.

Run from the repo root::

    python scenarios/departing_engineer/build.py

The incident: an engineer with a scheduled departure mints a GitHub token, then
23 minutes later begins first-ever access to restricted repositories, clones 19
of them in 11 minutes, builds an encrypted archive, copies it to removable media,
stops endpoint telemetry, and deletes shell history — with no approved change
ticket. The benign mirror of this exact activity (authorised migration) lives in
the negative condition: add an approval and the case evaporates.

Only 6 of the 19 clones ever receive *file-level* classification, which is what
makes the v2 rule regress — see ``_repository_collection_v2.py`` and
``ariadne diff``.
"""

from __future__ import annotations

import json
from pathlib import Path

from ariadne.lab.synthetic import SyntheticEnterprise, make_event, write_jsonl

HERE = Path(__file__).parent
ACTOR = "mcaney"
DEVICE = "WS-MCANEY-01"


def build() -> tuple[list, dict]:
    enterprise = SyntheticEnterprise(seed=42, employees=40)
    events = enterprise.background_noise(600, window_minutes=240)

    chain: list = []

    # A GitHub PAT minted 23 minutes before collection begins (collection at t=64).
    chain.append(
        make_event(
            "E1000", "github.token.create", 41, source="github_audit",
            user_id=ACTOR, device_id=DEVICE, device_enrolled=True,
            token_name="cli-automation", scopes="repo,read:org",
        )
    )

    # 19 first-seen restricted clones across 11 minutes; only 6 carry file-level
    # classification, the rest only repository-level.
    for index in range(19):
        offset = 64.0 + index * (11.0 / 18.0)
        attrs = dict(
            repository=f"restricted/proj-{index:02d}",
            repository_sensitivity="restricted",
            access_is_first_seen=True,
        )
        if index < 6:
            attrs["file_sensitivity"] = "restricted"
        chain.append(
            make_event(
                f"E{1001 + index}", "github.repository.clone", offset,
                source="github_audit", user_id=ACTOR, device_id=DEVICE,
                device_enrolled=True, **attrs,
            )
        )

    # Archive, staging, telemetry kill, history wipe — all endpoint (osquery) so a
    # source-wide clock skew shifts them together and the chain order is preserved.
    chain.append(
        make_event("E1020", "process.execution", 80, source="osquery",
                   user_id=ACTOR, device_id=DEVICE, device_enrolled=True,
                   process_name="gpg", command_line="gpg -c collection.tar")
    )
    chain.append(
        make_event("E1021", "filesystem.write", 82, source="osquery",
                   user_id=ACTOR, device_id=DEVICE, device_enrolled=True,
                   destination_type="removable_media", path="/mnt/usb/collection.tar.gpg",
                   bytes=734003200)
    )
    chain.append(
        make_event("E1022", "security.telemetry_state", 84, source="osquery",
                   user_id=ACTOR, device_id=DEVICE, device_enrolled=True,
                   state="stopped", telemetry_source="endpoint")
    )
    chain.append(
        make_event("E1023", "filesystem.delete", 86, source="osquery",
                   user_id=ACTOR, device_id=DEVICE, device_enrolled=True,
                   path="/home/mcaney/.bash_history")
    )
    # Network stays live after endpoint telemetry dies — selective blinding, and a
    # large encrypted upload to boot.
    chain.append(
        make_event("E1024", "network.connection", 88, source="zeek",
                   user_id=ACTOR, device_id=DEVICE,
                   bytes_out=734003200, destination="storage.example-personal.com",
                   destination_is_first_seen=True)
    )

    events.extend(chain)

    manifest = {
        "id": "departing-engineer",
        "title": "Departing engineer — restricted repository collection and staging",
        "description": (
            "An engineer with a scheduled departure collects restricted source code "
            "and stages it to removable media while degrading telemetry."
        ),
        "detections": ["ARI-IR-0042"],
        "facts": {
            "legitimate_access": True,
            "contradictory": [
                "User has legitimate engineering access",
                "Activity originated from an enrolled corporate device",
            ],
            "missing_evidence": [
                "Manager approval",
                "Change ticket",
                "DLP classification result",
            ],
        },
        "expected": {
            "cases": 1,
            "detections_triggered": 1,
            "primary_hypothesis": "H1",
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
