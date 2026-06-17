"""Reproducible ARIADNE benchmark harness.

Measures the numbers the benchmark page should publish — ingestion throughput,
per-detection evaluation latency (p50/p99), end-to-end replay duration, and peak
memory — against a synthetic dataset of a configurable size. Nothing here is
hand-typed into a README: run it and it prints (and writes) what it actually
observed on the machine it ran on.

Usage::

    python benchmarks/run.py --events 200000 --repeats 40
    python benchmarks/run.py --events 5000 --json benchmarks/results/ci.json
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import time
import tracemalloc
from datetime import timedelta
from pathlib import Path

from ariadne.engines.reference import ReferenceEngine
from ariadne.events.normalization import normalize_record, prepare
from ariadne.lab.synthetic import SyntheticEnterprise, make_event
from ariadne.rules.compiler import compile_detection
from ariadne.rules.loader import load_detections

ROOT = Path(__file__).resolve().parents[1]


def build_dataset(n_events: int, *, incidents: int = 5) -> list:
    """A large benign stream with a handful of embedded firing incidents."""

    enterprise = SyntheticEnterprise(seed=2026, employees=500)
    events = enterprise.background_noise(n_events, window_minutes=24 * 60)

    for incident in range(incidents):
        actor = f"target{incident:02d}"
        device = f"WS-T{incident:02d}"
        base_min = 100.0 + incident * 200
        for index in range(10):
            events.append(
                make_event(
                    f"INC{incident}-C{index}", "github.repository.clone",
                    base_min + index * 0.5, source="github_audit",
                    user_id=actor, device_id=device, device_enrolled=True,
                    repository_sensitivity="restricted", access_is_first_seen=True,
                )
            )
        events.append(make_event(f"INC{incident}-P", "process.execution", base_min + 16, source="osquery", user_id=actor, device_id=device, device_enrolled=True, process_name="gpg"))
        events.append(make_event(f"INC{incident}-W", "filesystem.write", base_min + 18, source="osquery", user_id=actor, device_id=device, device_enrolled=True, destination_type="removable_media"))
        events.append(make_event(f"INC{incident}-T", "security.telemetry_state", base_min + 20, source="osquery", user_id=actor, device_id=device, device_enrolled=True, state="stopped", telemetry_source="endpoint"))
    return events


def measure(n_events: int, repeats: int) -> dict:
    detections = [compile_detection(d) for d in load_detections(ROOT / "rules")]
    engine = ReferenceEngine()

    tracemalloc.start()
    events = build_dataset(n_events)

    # Serialize to raw records to time the normalizer realistically.
    raw = [e.model_dump(mode="json") for e in events]

    t0 = time.perf_counter()
    normalized = [normalize_record(r) for r in raw]
    prepared = prepare(normalized)
    ingestion_seconds = time.perf_counter() - t0
    ingestion_rate = len(raw) / ingestion_seconds if ingestion_seconds else 0.0

    # Steady-state matching latency: events are already normalized and ordered,
    # so this isolates grouping + sequence matching from ingestion cost.
    latencies_ms: list[float] = []
    cases = 0
    for _ in range(repeats):
        for detection in detections:
            t = time.perf_counter()
            result = engine.evaluate_prepared(prepared, detection)
            latencies_ms.append((time.perf_counter() - t) * 1000.0)
            cases += len(result.alerts)

    t0 = time.perf_counter()
    for detection in detections:
        engine.evaluate_prepared(prepared, detection)
    replay_seconds = time.perf_counter() - t0

    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    latencies_ms.sort()
    return {
        "hardware": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "processor": platform.processor() or "unknown",
        },
        "dataset": {
            "events": len(prepared),
            "detections": len(detections),
        },
        "results": {
            "ingestion_events_per_second": round(ingestion_rate),
            "p50_detection_latency_ms": round(statistics.median(latencies_ms), 2),
            "p99_detection_latency_ms": round(_percentile(latencies_ms, 0.99), 2),
            "replay_seconds": round(replay_seconds, 3),
            "peak_memory_mb": round(peak / (1024 * 1024), 1),
            "alerts_per_pass": cases // max(repeats, 1),
        },
    }


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    index = min(len(values) - 1, int(q * len(values)))
    return values[index]


def render(report: dict) -> str:
    hw, ds, res = report["hardware"], report["dataset"], report["results"]
    return "\n".join(
        [
            "Hardware:",
            f"  {hw['platform']}",
            f"  Python {hw['python']}",
            "",
            "Dataset:",
            f"  {ds['events']:,} normalized events",
            f"  {ds['detections']} sequence detections",
            "",
            "Results:",
            f"  Ingestion: {res['ingestion_events_per_second']:,} events/second",
            f"  P50 detection latency: {res['p50_detection_latency_ms']} ms",
            f"  P99 detection latency: {res['p99_detection_latency_ms']} ms",
            f"  Replay duration: {res['replay_seconds']} s",
            f"  Peak memory: {res['peak_memory_mb']} MB",
        ]
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="ARIADNE benchmark harness")
    parser.add_argument("--events", type=int, default=20000)
    parser.add_argument("--repeats", type=int, default=20)
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args()

    report = measure(args.events, args.repeats)
    print(render(report))
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + "\n")
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
