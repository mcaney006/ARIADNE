"""Chain-of-custody records for evidence objects.

ARIADNE's promise is that every conclusion traces back to bytes. This module
models the acquisition metadata and custody chain attached to an evidence
object (an archive, a log slice, a memory image) so that the investigation
output can cite *where* a fact came from and *who* has touched it since.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


class CustodyEntry(BaseModel):
    """A single transfer or access in an evidence object's history."""

    model_config = ConfigDict(frozen=True)

    actor: str
    action: str
    at: datetime = Field(default_factory=_now)
    note: str | None = None


class EvidenceObject(BaseModel):
    """An immutable artifact with an auditable custody chain.

    The ``sha256`` is computed at acquisition and never recomputed silently;
    :meth:`verify` re-hashes supplied bytes against the recorded digest so a
    reviewer can confirm an artifact has not been altered.
    """

    model_config = ConfigDict(frozen=True)

    object_id: str
    kind: str
    sha256: str
    size_bytes: int
    acquired_at: datetime = Field(default_factory=_now)
    acquired_by: str = "ariadne"
    source_ref: str | None = None
    custody: tuple[CustodyEntry, ...] = ()

    @classmethod
    def acquire(
        cls,
        object_id: str,
        kind: str,
        data: bytes,
        *,
        acquired_by: str = "ariadne",
        source_ref: str | None = None,
    ) -> EvidenceObject:
        """Acquire an evidence object from raw bytes, sealing its digest."""

        digest = hashlib.sha256(data).hexdigest()
        first = CustodyEntry(actor=acquired_by, action="acquired", note=source_ref)
        return cls(
            object_id=object_id,
            kind=kind,
            sha256=digest,
            size_bytes=len(data),
            acquired_by=acquired_by,
            source_ref=source_ref,
            custody=(first,),
        )

    def verify(self, data: bytes) -> bool:
        """Return whether ``data`` matches the sealed digest."""

        return hashlib.sha256(data).hexdigest() == self.sha256

    def transfer(self, actor: str, action: str, note: str | None = None) -> EvidenceObject:
        """Return a copy with one more custody entry appended."""

        entry = CustodyEntry(actor=actor, action=action, note=note)
        return self.model_copy(update={"custody": (*self.custody, entry)})
