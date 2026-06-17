"""AWS CloudTrail -> normalized event.

CloudTrail records an ``eventName`` (``GetObject``, ``CreateUser``, ...) under an
``eventTime`` ISO timestamp, with the caller in ``userIdentity``. This maps the
S3 read and the IAM identity lifecycle events the cloud and privileged-admin
rules depend on, preserving the ARN as the actor's source identity.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ariadne.events.schema import Actor, Event, Provenance

_EVENT_MAP = {
    "GetObject": "aws.s3.get_object",
    "CreateUser": "iam.user.create",
    "DeleteUser": "iam.user.delete",
    "PutUserPolicy": "iam.policy.change",
    "AttachUserPolicy": "iam.policy.change",
}


def from_cloudtrail_record(record: dict[str, Any]) -> Event:
    name = record.get("eventName", "")
    event_type = _EVENT_MAP.get(name, f"aws.{name.lower()}")
    event_time = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
    identity = record.get("userIdentity", {})
    params = record.get("requestParameters", {}) or {}

    attributes: dict[str, Any] = {"aws_region": record.get("awsRegion")}
    if event_type == "aws.s3.get_object":
        attributes["bucket"] = params.get("bucketName")
        attributes["key"] = params.get("key")
    if event_type in {"iam.user.create", "iam.user.delete"}:
        attributes["target_user"] = params.get("userName")

    return Event(
        event_id=record.get("eventID") or f"ct-{record.get('eventTime')}",
        event_type=event_type,
        event_time=event_time,
        actor=Actor(
            user_id=identity.get("userName") or identity.get("principalId"),
            source_identity=identity.get("arn"),
        ),
        attributes=attributes,
        provenance=Provenance(source="cloudtrail", collector="cloudtrail", raw_ref=record.get("eventID")),
    )
