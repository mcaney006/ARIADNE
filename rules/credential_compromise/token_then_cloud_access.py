"""Credential-compromise detection: new token, foreign auth, then cloud pull.

The shape that distinguishes a stolen credential from a malicious insider is the
*absence* of the human's endpoint. A freshly minted access token used from
unfamiliar infrastructure to enumerate repositories and pull cloud objects —
while the employee's enrolled laptop shows nothing — is far more consistent with
compromise than with the employee acting in person. The investigator's hypothesis
model is what turns that shape into the conclusion; this rule supplies the chain.
"""

from ariadne.rules import Count, Detection, Event, Sequence

token_then_cloud_access = Detection(
    id="ARI-CC-0017",
    title="New token used from unusual infrastructure to enumerate and pull cloud data",
    severity="high",
    version="1",
    join_by=("actor.user_id",),
    description=(
        "Personal access token creation followed by authentication from unusual "
        "infrastructure, repository enumeration, and cloud object retrieval."
    ),
    tags=("credential-compromise", "T1078", "T1530"),
    sequence=Sequence(
        within="30m",
        steps=[
            Event("github.token.create"),
            Event("identity.authentication").where(infrastructure_is_unusual=True),
            Count(
                Event("github.repository.clone"),
                at_least=5,
                within="10m",
            ),
            Event("aws.s3.get_object").where(object_is_restricted=True),
        ],
    ),
)

DETECTIONS = [token_then_cloud_access]
