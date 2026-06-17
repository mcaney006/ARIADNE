"""Identity resolution: many identifiers, one human.

A single person appears as a GitHub login, a unix uid, an AWS principal, a VPN
name, an email. ARIADNE resolves them into one principal while keeping the
confidence and provenance of every link, because insider risk is about
understanding the human operating through many systems — not about any single
log line.
"""

from ariadne.identity.confidence import merge_confidence, path_confidence
from ariadne.identity.graph import IdentityAssertion, IdentityLink
from ariadne.identity.resolver import IdentityResolver, Principal, ResolvedIdentity

__all__ = [
    "IdentityAssertion",
    "IdentityLink",
    "IdentityResolver",
    "Principal",
    "ResolvedIdentity",
    "merge_confidence",
    "path_confidence",
]
