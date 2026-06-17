"""The local evaluation engines.

:class:`~ariadne.engines.reference.ReferenceEngine` is the deterministic,
event-time batch evaluator that every other component treats as ground truth.
:class:`~ariadne.engines.reference.StreamingEvaluator` wraps it with watermark
admission so the same detection can be driven by an out-of-order, duplicated,
reconnecting feed and still produce identical results.
"""

from ariadne.engines.reference import (
    EvaluationResult,
    ReferenceEngine,
    SequenceMatch,
    StreamingEvaluator,
)
from ariadne.engines.windows import WatermarkTracker

__all__ = [
    "EvaluationResult",
    "ReferenceEngine",
    "SequenceMatch",
    "StreamingEvaluator",
    "WatermarkTracker",
]
