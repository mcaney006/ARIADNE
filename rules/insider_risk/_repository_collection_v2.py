"""Version 2 of the repository-collection detection — kept for regression demos.

This is the *cautionary* version. A well-meaning edit tightened the count step to
require a per-file ``file_sensitivity`` classification of "restricted" instead of
the repository-level ``repository_sensitivity``. On paper it is more precise; in
practice a large share of clone events never receive file-level classification,
so the detection silently stops firing. ``ariadne diff`` exists to catch exactly
this. The leading underscore keeps the file out of the default rule pack; load it
by explicit path for the diff demonstration.
"""

from ariadne.rules import Absence, Count, Detection, Event, Sequence

repository_collection_v2 = Detection(
    id="ARI-IR-0042",
    title="Restricted repository collection followed by data staging",
    severity="critical",
    version="2",
    join_by=("actor.user_id", "device.id"),
    description="Version 2: requires per-file classification telemetry (regression-prone).",
    tags=("insider-risk", "exfiltration", "T1567", "T1560"),
    sequence=Sequence(
        within="45m",
        steps=[
            Count(
                Event("github.repository.clone").where(
                    file_sensitivity="restricted",
                    access_is_first_seen=True,
                ),
                at_least=8,
                within="15m",
            ),
            Event("process.execution").where(
                process_name__in={"zip", "7z", "tar", "gpg"},
            ),
            Event("filesystem.write").where(
                destination_type__in={"removable_media", "cloud_sync_folder"},
            ),
            Event("security.telemetry_state").where(
                state__in={"stopped", "disabled", "degraded"},
            ),
        ],
    ),
    exceptions=[
        Absence(
            Event("change_management.approval").where(approval_status="approved"),
            within="24h",
        ),
    ],
)

DETECTIONS = [repository_collection_v2]
