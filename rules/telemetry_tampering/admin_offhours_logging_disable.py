"""Privileged-administrator abuse: off-hours logging disable and identity churn.

Administrators legitimately do high-risk things all day, so volume alone is
useless here. The anomalous *sequence* is what matters: acting outside the
approved maintenance window, from a previously unseen device, disabling logging,
minting a temporary privileged identity, pulling restricted evidence, and then
deleting that identity to erase the trail. Each step is plausible alone; together,
within an hour, and unapproved, they are not.
"""

from ariadne.rules import Absence, Detection, Event, Sequence

admin_offhours_logging_disable = Detection(
    id="ARI-TT-0009",
    title="Off-hours administrative logging disable with temporary privileged identity",
    severity="critical",
    version="1",
    join_by=("actor.user_id",),
    description=(
        "Administrator acts outside the maintenance window from an unseen device, "
        "disables logging, creates and later deletes a temporary privileged identity, "
        "and retrieves restricted evidence."
    ),
    tags=("telemetry-tampering", "privilege-abuse", "T1562", "T1078.004"),
    sequence=Sequence(
        within="60m",
        steps=[
            Event("identity.authentication").where(
                outside_maintenance_window=True,
                device_is_first_seen=True,
            ),
            Event("security.telemetry_state").where(
                state__in={"stopped", "disabled", "degraded"},
                telemetry_source__in={"audit", "logging", "cloudtrail"},
            ),
            Event("iam.user.create").where(privileged=True),
            Event("aws.s3.get_object").where(object_is_restricted=True),
            Event("iam.user.delete").where(privileged=True),
        ],
    ),
    exceptions=[
        Absence(
            Event("change_management.approval").where(approval_status="approved"),
            within="24h",
        ),
    ],
)

DETECTIONS = [admin_offhours_logging_disable]
