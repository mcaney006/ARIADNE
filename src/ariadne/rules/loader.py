"""Load detection objects from Python rule files.

Rule packs are ordinary Python modules that define :class:`Detection` objects at
module scope (optionally collected in a ``DETECTIONS`` list). This loader imports
a file or a directory tree of them by path and returns every detection it finds,
so the CLI can point at ``rules/insider_risk`` and get a pack without an import
ceremony.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from ariadne.rules.dsl import Detection


def _load_module(path: Path):
    spec = importlib.util.spec_from_file_location(f"ariadne_rule_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot import rule file: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _detections_from_module(module) -> list[Detection]:
    # A module's DETECTIONS list, when present, is authoritative: it lets a rule
    # file keep helper or alternate-version detections at module scope without
    # leaking them into the pack.
    explicit = getattr(module, "DETECTIONS", None)
    if isinstance(explicit, (list, tuple)):
        return [d for d in explicit if isinstance(d, Detection)]
    found: list[Detection] = []
    for name, value in vars(module).items():
        if name.startswith("_"):
            continue
        if isinstance(value, Detection) and value not in found:
            found.append(value)
    return found


def load_detections(path: str | Path) -> list[Detection]:
    """Load all detections from a ``.py`` file or a directory of them."""

    root = Path(path)
    files: list[Path]
    if root.is_dir():
        files = sorted(p for p in root.rglob("*.py") if not p.name.startswith("_"))
    else:
        files = [root]

    detections: list[Detection] = []
    for file in files:
        module = _load_module(file)
        detections.extend(_detections_from_module(module))

    # Deduplicate by (id, version) while preserving order.
    seen: set[tuple[str, str]] = set()
    unique: list[Detection] = []
    for detection in detections:
        key = (detection.id, detection.version)
        if key not in seen:
            seen.add(key)
            unique.append(detection)
    return unique


def index_by_id(detections: list[Detection]) -> dict[str, Detection]:
    """Index detections by id, latest version wins on collision."""

    index: dict[str, Detection] = {}
    for detection in detections:
        index[detection.id] = detection
    return index
