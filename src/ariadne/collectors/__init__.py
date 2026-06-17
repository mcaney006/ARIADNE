"""Collectors: source-specific adapters that emit normalized events.

A collector's only job is to turn one telemetry source's native shape into the
canonical :class:`~ariadne.events.schema.Event`. Everything downstream — the
engine, the investigation, the replay lab — depends only on the normalized form,
so adding a source is a self-contained adapter and never a change to the core.

The adapters here are deliberately fixture-driven: they parse representative
records from osquery, Zeek, the GitHub audit log, and AWS CloudTrail. A live
connector is the same function with a real client in front of it; the mapping to
the normalized model is the part that matters and the part that is implemented.
"""

from ariadne.collectors.cloudtrail import from_cloudtrail_record
from ariadne.collectors.github import from_github_audit_record
from ariadne.collectors.osquery import from_osquery_row
from ariadne.collectors.zeek import from_zeek_conn

__all__ = [
    "from_cloudtrail_record",
    "from_github_audit_record",
    "from_osquery_row",
    "from_zeek_conn",
]
