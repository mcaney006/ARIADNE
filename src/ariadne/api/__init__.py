"""The FastAPI + HTMX investigation console.

Deliberately thin: it renders the same :class:`~ariadne.investigation.case.Case`
objects the CLI and tests produce into the five-panel case view (thesis, event
thread, why-it-fired, alternative explanations, durability). The spectacle lives
in the engine; this is the window onto it.

Importing this module requires the optional ``ui`` extra (FastAPI + Jinja2).
"""

from ariadne.api.app import app, create_app

__all__ = ["app", "create_app"]
