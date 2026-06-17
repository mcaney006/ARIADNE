"""Smoke tests for the FastAPI console (skipped unless the 'ui' extra is present)."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from ariadne.api.app import create_app  # noqa: E402


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(create_app())


def test_index_lists_scenarios_and_rules(client):
    body = client.get("/").text
    assert "Scenarios" in body
    assert "ARI-IR-0042" in body


def test_case_page_renders_five_panels(client):
    body = client.get("/scenario/departing_engineer").text
    assert client.get("/scenario/departing_engineer").status_code == 200
    for panel in [
        "Investigation thesis",
        "Event thread",
        "Why this fired",
        "Alternative explanations",
        "Detection durability",
    ]:
        assert panel in body
    assert "Minimal decisive evidence" in body


def test_rule_page_shows_ir_and_compilations(client):
    body = client.get("/rule/ARI-IR-0042").text
    assert "windowFunnel" in body
    assert "sequence by" in body


def test_unknown_scenario_is_404(client):
    assert client.get("/scenario/does-not-exist").status_code == 404
