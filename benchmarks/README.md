# Benchmarks

These numbers are produced by a harness you can run, not typed into a table by
hand. `benchmarks/run.py` builds a synthetic dataset of a configurable size (a
500-employee enterprise's benign noise with a handful of embedded firing
incidents), then measures four things against the shipped rule pack:

- **Ingestion throughput** — raw records per second through
  `normalize_record` + canonical ordering + idempotent dedup.
- **Detection latency (p50/p99)** — steady-state per-detection evaluation over
  already-normalized events (`ReferenceEngine.evaluate_prepared`), so it isolates
  grouping and sequence matching from ingestion cost.
- **Replay duration** — wall-clock to evaluate the whole pack once.
- **Peak memory** — via `tracemalloc`.

## Running

```bash
python benchmarks/run.py --events 50000 --repeats 30
python benchmarks/run.py --events 5000 --repeats 50 --json benchmarks/results/sample.json
```

## Honesty notes

The numbers are machine-dependent and the reference engine is **pure Python** —
it is the deterministic ground truth, not the high-volume execution path. For
production-scale volumes the IR compiles to ClickHouse (`windowFunnel` +
`countIf`); see `src/ariadne/compilers/clickhouse.py`. Latency scales with corpus
size because the reference engine rescans; a windowed/stateful deployment pays
per-event, not per-corpus.

CI runs this harness at a small, fast scale on every push and uploads the result
as an artifact, so the trend is reproducible rather than aspirational. A sample
result lives at [`results/sample.json`](results/sample.json).
