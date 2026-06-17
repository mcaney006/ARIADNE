from datetime import timedelta

import pytest

from ariadne.rules.compiler import compile_detection
from ariadne.rules.validation import has_errors, lint
from ariadne.timeutil import format_duration, parse_duration


def test_parse_duration():
    assert parse_duration("45m") == timedelta(minutes=45)
    assert parse_duration("24h") == timedelta(hours=24)
    assert parse_duration("30s") == timedelta(seconds=30)
    assert parse_duration("7d") == timedelta(days=7)
    assert parse_duration(timedelta(minutes=5)) == timedelta(minutes=5)
    assert parse_duration(90) == timedelta(seconds=90)


def test_parse_duration_rejects_garbage():
    with pytest.raises(ValueError):
        parse_duration("soon")


def test_format_duration_roundtrips_clean_units():
    assert format_duration(timedelta(minutes=45)) == "45m"
    assert format_duration(timedelta(hours=24)) == "1d"
    assert format_duration(timedelta(seconds=256)) == "4m16s"


def test_lint_clean_detection(detection):
    findings = lint(compile_detection(detection))
    assert not has_errors(findings)
