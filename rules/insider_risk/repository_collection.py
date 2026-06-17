"""Insider-risk detection: restricted repository collection followed by staging.

This is the flagship detection. It fires when one actor, on one device, clones a
burst of restricted repositories they have never accessed before, then creates an
archive, stages it to removable media or a cloud-sync folder, and finally
degrades endpoint telemetry — all inside 45 minutes and *without* an approved
change ticket. The negative condition is what makes it contextual rather than a
keyword match: the identical technical activity, authorised, does not alert.
"""

from ariadne.rules import Absence, Count, Detection, Event, Sequence

repository_collection = Detection(
    id="ARI-IR-0042",
    title="Restricted repository collection followed by data staging",
    severity="critical",
    version="1",
    join_by=("actor.user_id", "device.id"),
    description=(
        "Bulk first-seen restricted repository cloning, archive creation, "
        "removable-media staging, and telemetry degradation with no approved change."
    ),
    tags=("insider-risk", "exfiltration", "T1567", "T1560"),
    sequence=Sequence(
        within="45m",
        steps=[
            Count(
                Event("github.repository.clone").where(
                    repository_sensitivity="restricted",
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

DETECTIONS = [repository_collection]
