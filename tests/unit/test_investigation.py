from ariadne.investigation.hypotheses import default_hypotheses, evaluate_hypotheses
from ariadne.investigation.investigator import Investigator
from tests.conftest import ev, firing_chain


def test_hypothesis_scoring_is_explainable():
    signals = {"bulk_restricted_clone": True, "archive_created": True, "removable_media_write": True}
    scores = evaluate_hypotheses(default_hypotheses(), signals)
    # Probabilities form a distribution.
    assert abs(sum(s.probability for s in scores) - 1.0) < 1e-9
    top = scores[0]
    assert top.hypothesis.id == "H1"
    assert any(i.signal == "bulk_restricted_clone" for i in top.supporting)


def test_case_has_minimal_evidence_and_durability(detection):
    events = firing_chain()
    case = Investigator().investigate(events, detection, facts={"legitimate_access": True})
    assert case is not None
    assert case.risk >= 80
    assert case.confidence == "High"
    # Minimal evidence = 8 clones + 3 staging events.
    assert len(case.minimal_evidence) == 11
    assert case.primary_hypothesis.hypothesis.id == "H1"


def test_no_case_when_suppressed(detection):
    events = firing_chain() + [ev("AP", "change_management.approval", -10, approval_status="approved")]
    assert Investigator().investigate(events, detection) is None


def test_timeline_detects_selective_blinding(detection):
    events = firing_chain()
    events.append(ev("Z", "network.connection", 25, source="zeek", bytes_out=10**8))
    case = Investigator().investigate(events, detection, facts={})
    gap_rows = [e for e in case.timeline.entries if e.is_gap]
    assert gap_rows, "expected a telemetry-gap annotation after the endpoint stop"
