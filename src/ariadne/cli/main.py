"""``ariadne`` — the detection-engineering command line.

The verbs mirror the workflow: inspect a rule, compile it to a SIEM, replay a
recorded incident, explain why a case fired, and diff two rule versions to catch
regressions. Everything routes through the same library the tests use, so the CLI
is a thin presentation layer over deterministic machinery.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from ariadne.compilers import COMPILERS
from ariadne.investigation.investigator import Investigator
from ariadne.replay.differential import diff_detections
from ariadne.replay.runner import Scenario, ScenarioRunner
from ariadne.rules.ast import render_tree
from ariadne.rules.compiler import compile_detection
from ariadne.rules.loader import index_by_id, load_detections
from ariadne.rules.validation import lint

app = typer.Typer(
    add_completion=False,
    help="ARIADNE — deterministic insider-risk detection compiler and forensic replay engine.",
    no_args_is_help=True,
)
rules_app = typer.Typer(help="Inspect and validate detection rules.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")


def _pick(detections, detection_id: Optional[str]):
    if not detections:
        raise typer.BadParameter("no detections found")
    if detection_id:
        for detection in detections:
            if detection.id == detection_id:
                return detection
        raise typer.BadParameter(f"detection id {detection_id!r} not found")
    return detections[0]


@app.command()
def version() -> None:
    """Print the ARIADNE version."""

    from ariadne import __version__

    typer.echo(f"ariadne {__version__}")


@app.command()
def replay(
    scenario: Path = typer.Argument(..., help="Scenario directory to replay."),
    rules: Path = typer.Option(Path("rules"), "--rules", "-r", help="Rule pack directory."),
    explain: bool = typer.Option(False, "--explain", help="Render the full case for each firing."),
    durability: bool = typer.Option(True, "--durability/--no-durability"),
) -> None:
    """Replay a recorded incident through the current detection pack."""

    detections = load_detections(rules)
    loaded = Scenario.load(scenario)
    runner = ScenarioRunner(detections, with_durability=durability)
    report = runner.run(loaded)
    typer.echo(report.render())
    if explain:
        for case in report.cases:
            typer.echo("\n" + "=" * 60)
            typer.echo(case.render())


@app.command()
def diff(
    rules_v1: Path = typer.Argument(..., help="Rule pack for version 1."),
    rules_v2: Path = typer.Argument(..., help="Rule pack for version 2."),
    scenario: Path = typer.Argument(..., help="Scenario directory to diff against."),
    detection_id: Optional[str] = typer.Option(None, "--id", help="Limit to one detection id."),
) -> None:
    """Compare two rule versions against a scenario and explain regressions."""

    v1 = index_by_id(load_detections(rules_v1))
    v2 = index_by_id(load_detections(rules_v2))
    loaded = Scenario.load(scenario)

    shared = sorted(set(v1) & set(v2))
    if detection_id:
        shared = [detection_id] if detection_id in shared else []
    if not shared:
        raise typer.BadParameter("no detection id is present in both rule packs")

    first = True
    for det_id in shared:
        result = diff_detections(loaded.events, v1[det_id], v2[det_id])
        if not first:
            typer.echo("\n" + "-" * 60)
        first = False
        typer.echo(result.render())


@app.command()
def compile(
    rule_file: Path = typer.Argument(..., help="Rule file or directory."),
    target: str = typer.Option("eql", "--target", "-t", help="eql | spl | kql | clickhouse"),
    detection_id: Optional[str] = typer.Option(None, "--id", help="Detection id to compile."),
) -> None:
    """Compile a detection to a SIEM query language."""

    if target not in COMPILERS:
        raise typer.BadParameter(f"unknown target {target!r}; choose from {sorted(COMPILERS)}")
    detection = _pick(load_detections(rule_file), detection_id)
    ir = compile_detection(detection)
    typer.echo(COMPILERS[target](ir))


@app.command()
def explain(
    rule_file: Path = typer.Argument(..., help="Rule file or directory."),
    scenario: Path = typer.Argument(..., help="Scenario directory."),
    detection_id: Optional[str] = typer.Option(None, "--id", help="Detection id to explain."),
) -> None:
    """Explain why (or whether) a detection fires on a scenario."""

    detection = _pick(load_detections(rule_file), detection_id)
    loaded = Scenario.load(scenario)
    case = Investigator().investigate(loaded.events, detection, facts=loaded.facts)
    if case is None:
        typer.echo(f"{detection.id}: no case — the detection did not fire on this scenario")
        raise typer.Exit(code=0)
    typer.echo(case.render())
    typer.echo("\nWhy this fired:")
    for line in case.explanation:
        typer.echo(f"  {line}")


@app.command()
def console(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
    rules: Path = typer.Option(Path("rules"), "--rules", "-r"),
    scenarios: Path = typer.Option(Path("scenarios"), "--scenarios"),
) -> None:
    """Serve the FastAPI investigation console (requires the 'ui' extra)."""

    try:
        import uvicorn

        from ariadne.api.app import create_app
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise typer.BadParameter(
            "the console needs the 'ui' extra: pip install 'ariadne-ir[ui]'"
        ) from exc

    typer.echo(f"ARIADNE console on http://{host}:{port}")
    uvicorn.run(create_app(str(rules), str(scenarios)), host=host, port=port)


@rules_app.command("list")
def rules_list(
    rules: Path = typer.Argument(Path("rules"), help="Rule pack directory."),
) -> None:
    """List detections in a rule pack."""

    for detection in load_detections(rules):
        typer.echo(f"{detection.id}@v{detection.version}  [{detection.severity}]  {detection.title}")


@rules_app.command("show")
def rules_show(
    rule_file: Path = typer.Argument(..., help="Rule file or directory."),
    detection_id: Optional[str] = typer.Option(None, "--id"),
) -> None:
    """Render a detection's intermediate representation as a tree."""

    detection = _pick(load_detections(rule_file), detection_id)
    typer.echo(render_tree(compile_detection(detection)))


@rules_app.command("validate")
def rules_validate(
    rules: Path = typer.Argument(Path("rules"), help="Rule pack directory."),
) -> None:
    """Lint a rule pack and report findings."""

    problems = 0
    for detection in load_detections(rules):
        findings = lint(compile_detection(detection))
        for finding in findings:
            problems += 1
            typer.echo(f"{detection.id}: [{finding.level}] {finding.code} — {finding.message}")
    if problems == 0:
        typer.echo("no lint findings")


if __name__ == "__main__":
    app()
