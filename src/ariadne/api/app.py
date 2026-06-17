"""ARIADNE investigation console (FastAPI).

Routes:

- ``GET /``                 — the scenario index and the loaded detection pack.
- ``GET /scenario/{name}``  — replay a scenario and render its case.
- ``GET /rule/{rule_id}``   — the rule's IR tree and its SIEM compilations.

Run it with::

    uvicorn ariadne.api.app:app --reload
    # or: ariadne console
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ariadne.compilers import COMPILERS
from ariadne.replay.runner import Scenario, ScenarioRunner
from ariadne.rules.ast import render_tree
from ariadne.rules.compiler import compile_detection
from ariadne.rules.loader import index_by_id, load_detections

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def create_app(rules_dir: str | None = None, scenarios_dir: str | None = None) -> FastAPI:
    rules_path = Path(rules_dir or os.environ.get("ARIADNE_RULES", "rules"))
    scenarios_path = Path(scenarios_dir or os.environ.get("ARIADNE_SCENARIOS", "scenarios"))

    app = FastAPI(title="ARIADNE Console")
    detections = load_detections(rules_path)
    by_id = index_by_id(detections)
    runner = ScenarioRunner(detections)

    def scenario_dirs() -> list[Path]:
        return sorted(p.parent for p in scenarios_path.glob("*/scenario.json"))

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        scenarios = []
        for directory in scenario_dirs():
            scenario = Scenario.load(directory)
            scenarios.append({"name": directory.name, "title": scenario.title})
        rules = [
            {"id": d.id, "title": d.title, "severity": d.severity, "version": d.version}
            for d in detections
        ]
        return TEMPLATES.TemplateResponse(
            request, "index.html", {"scenarios": scenarios, "rules": rules}
        )

    @app.get("/scenario/{name}", response_class=HTMLResponse)
    def scenario_view(request: Request, name: str):
        directory = scenarios_path / name
        if not (directory / "scenario.json").exists():
            raise HTTPException(status_code=404, detail="scenario not found")
        scenario = Scenario.load(directory)
        report = runner.run(scenario)
        case = report.cases[0] if report.cases else None
        chain = _chain_nodes(case) if case else []
        return TEMPLATES.TemplateResponse(
            request,
            "case.html",
            {
                "scenario": scenario,
                "report": report,
                "case": case,
                "chain": chain,
            },
        )

    @app.get("/rule/{rule_id}", response_class=HTMLResponse)
    def rule_view(request: Request, rule_id: str):
        detection = by_id.get(rule_id)
        if detection is None:
            raise HTTPException(status_code=404, detail="rule not found")
        ir = compile_detection(detection)
        compilations = {name: compiler(ir) for name, compiler in COMPILERS.items()}
        return TEMPLATES.TemplateResponse(
            request,
            "rule.html",
            {
                "rule": detection,
                "tree": render_tree(ir),
                "compilations": compilations,
            },
        )

    return app


def _chain_nodes(case) -> list[dict]:
    """Collapse the matched assignment into a Person -> ... -> Destination thread."""

    nodes: list[dict] = []
    actor = case.match.join_values.get("actor.user_id", "actor")
    nodes.append({"label": "Person", "value": actor})
    device = case.match.join_values.get("device.id")
    if device:
        nodes.append({"label": "Device", "value": device})
    for step in case.match.assignment.steps:
        event = step.events[0]
        kind = event.event_type.split(".")[0]
        detail = (
            event.attributes.get("process_name")
            or event.attributes.get("destination_type")
            or event.attributes.get("state")
            or f"{len(step.events)}×"
        )
        nodes.append({"label": kind, "value": str(detail)})
    return nodes


app = create_app()
