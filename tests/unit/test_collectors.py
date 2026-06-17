from ariadne.collectors import (
    from_cloudtrail_record,
    from_github_audit_record,
    from_osquery_row,
    from_zeek_conn,
)
from ariadne.events.schema import resolve_field


def test_osquery_process_row():
    event = from_osquery_row(
        {
            "unixTime": 1770069600,
            "hostIdentifier": "WS-1",
            "columns": {"name": "gpg", "username": "mcaney", "pid": "42", "cmdline": "gpg -c x"},
        }
    )
    assert event.event_type == "process.execution"
    assert resolve_field(event, "actor.user_id") == "mcaney"
    assert resolve_field(event, "process_name") == "gpg"


def test_github_clone_and_token():
    clone = from_github_audit_record(
        {"action": "git.clone", "@timestamp": 1770069600000, "actor": "mcaney006", "repo": "acme/secret", "repository_visibility": "restricted"}
    )
    assert clone.event_type == "github.repository.clone"
    assert resolve_field(clone, "repository_sensitivity") == "restricted"
    token = from_github_audit_record(
        {"action": "personal_access_token.create", "@timestamp": 1770069600000, "actor": "mcaney006"}
    )
    assert token.event_type == "github.token.create"


def test_zeek_conn():
    event = from_zeek_conn({"ts": 1770069600.5, "uid": "C123", "id.orig_h": "10.0.0.5", "id.resp_h": "1.2.3.4", "orig_bytes": 999})
    assert event.event_type == "network.connection"
    assert resolve_field(event, "bytes_out") == 999


def test_cloudtrail_s3_and_iam():
    s3 = from_cloudtrail_record(
        {
            "eventName": "GetObject",
            "eventTime": "2026-02-02T22:00:00Z",
            "userIdentity": {"userName": "admin_kim", "arn": "arn:aws:iam::1:user/admin_kim"},
            "requestParameters": {"bucketName": "ir-evidence", "key": "x"},
        }
    )
    assert s3.event_type == "aws.s3.get_object"
    assert resolve_field(s3, "actor.source_identity").startswith("arn:aws:iam")
    iam = from_cloudtrail_record(
        {"eventName": "CreateUser", "eventTime": "2026-02-02T22:00:00Z", "userIdentity": {"userName": "admin_kim"}, "requestParameters": {"userName": "svc-temp"}}
    )
    assert iam.event_type == "iam.user.create"
