from ariadne.identity import (
    IdentityAssertion,
    IdentityLink,
    IdentityResolver,
    merge_confidence,
    path_confidence,
)


def test_confidence_arithmetic():
    assert path_confidence([0.9, 0.8]) == 0.9 * 0.8
    assert round(merge_confidence([0.8, 0.8]), 4) == 0.96


def test_resolves_one_principal_across_sources():
    resolver = IdentityResolver()
    resolver.add_assertion(IdentityAssertion("github_user", "mcaney006", "github_audit", 1.0))
    resolver.add_assertion(IdentityAssertion("email", "m@acme.com", "directory", 1.0))
    resolver.add_assertion(IdentityAssertion("unix_uid", "501", "osquery", 0.94))
    resolver.add_assertion(IdentityAssertion("aws_principal", "AROAEXAMPLE", "cloudtrail", 0.9))
    resolver.add_link(
        IdentityLink(("github_user", "mcaney006"), ("email", "m@acme.com"), 0.99, "directory")
    )
    resolver.add_link(
        IdentityLink(("email", "m@acme.com"), ("unix_uid", "501"), 0.95, "directory")
    )
    resolver.add_link(
        IdentityLink(("email", "m@acme.com"), ("aws_principal", "AROAEXAMPLE"), 0.92, "sso")
    )

    principals = resolver.resolve()
    assert len(principals) == 1
    principal = principals[0]
    assert principal.has("github_user", "mcaney006")
    assert principal.has("unix_uid", "501")
    # The uid is reachable only through two links, so its confidence is dampened.
    uid = next(i for i in principal.identities if i.type == "unix_uid")
    assert 0.0 < uid.confidence < 0.94


def test_unrelated_identities_stay_separate():
    resolver = IdentityResolver()
    resolver.add_assertion(IdentityAssertion("github_user", "alice", "github_audit", 1.0))
    resolver.add_assertion(IdentityAssertion("github_user", "bob", "github_audit", 1.0))
    assert len(resolver.resolve()) == 2


def test_shared_email_auto_links():
    resolver = IdentityResolver()
    resolver.add_assertion(IdentityAssertion("email", "x@acme.com", "okta", 1.0))
    resolver.add_assertion(IdentityAssertion("email", "x@acme.com", "github_audit", 1.0))
    # Same email value reported by two sources is treated as one atom anyway,
    # but a github login tied to it should merge through the shared value.
    resolver.add_assertion(IdentityAssertion("github_user", "xx", "github_audit", 1.0))
    resolver.add_link(IdentityLink(("github_user", "xx"), ("email", "x@acme.com"), 0.9, "directory"))
    assert len(resolver.resolve()) == 1
