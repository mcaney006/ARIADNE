# Evidence samples

ARIADNE's promise is that every conclusion traces back to bytes. An
`EvidenceObject` (`ariadne.events.provenance`) seals an artifact's SHA-256 at
acquisition and records an auditable custody chain; `verify(data)` re-hashes
supplied bytes against the sealed digest so a reviewer can confirm an artifact
has not been altered.

[`chain_of_custody.json`](chain_of_custody.json) is a generated example: a
synthetic encrypted archive acquired by a collector, reviewed by an analyst, then
sealed under legal hold. Regenerate it with:

```python
from ariadne.events.provenance import EvidenceObject
obj = EvidenceObject.acquire("evidence-0001", "encrypted_archive", data,
                             source_ref="/mnt/usb/collection.tar.gpg")
obj = obj.transfer("analyst-jdoe", "reviewed", "opened case ARI-2026-0042")
```

All sample data here is synthetic.
