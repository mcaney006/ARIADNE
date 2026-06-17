from ariadne.rules import compile_detection, render_tree
from ariadne.rules.dsl import Event as Pattern
from ariadne.rules.predicates import split_operator
from tests.conftest import ev


def test_split_operator():
    assert split_operator("process_name__in") == ("process_name", "in")
    assert split_operator("repository_sensitivity") == ("repository_sensitivity", "eq")
    assert split_operator("bytes__gte") == ("bytes", "gte")
    assert split_operator("path__not_in") == ("path", "not_in")


def test_where_is_functional_and_chainable():
    base = Pattern("github.repository.clone")
    specialised = base.where(repository_sensitivity="restricted").where(access_is_first_seen=True)
    assert base.conditions == ()
    assert len(specialised.conditions) == 2


def test_predicate_operators_match():
    clone = ev("E1", "github.repository.clone", 0, repository_sensitivity="restricted", bytes=500)
    assert Pattern("github.repository.clone").where(repository_sensitivity="restricted").matches(clone)
    assert Pattern("github.repository.clone").where(repository_sensitivity__ne="normal").matches(clone)
    assert Pattern("github.repository.clone").where(bytes__gte=500).matches(clone)
    assert not Pattern("github.repository.clone").where(bytes__gt=500).matches(clone)
    assert Pattern("github.repository.clone").where(repository_sensitivity__in={"restricted"}).matches(clone)
    assert Pattern("github.repository.clone").where(repository_sensitivity__regex="rest.*").matches(clone)


def test_missing_field_does_not_match_comparisons():
    clone = ev("E1", "github.repository.clone", 0)
    assert not Pattern("github.repository.clone").where(bytes__gt=0).matches(clone)
    assert not Pattern("github.repository.clone").where(repository_sensitivity="restricted").matches(clone)


def test_compile_and_render_tree(detection):
    ir = compile_detection(detection)
    assert ir.id == "ARI-IR-0042"
    assert len(ir.sequence.steps) == 4
    tree = render_tree(ir)
    assert "Count: github.repository.clone" in tree
    assert "threshold ≥ 8 within 15m" in tree
    assert "NegativeCondition" in tree
