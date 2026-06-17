from ariadne.compilers import COMPILERS, compile_clickhouse, compile_eql, compile_kql, compile_spl
from ariadne.rules.compiler import compile_detection


def test_eql_sequence_and_until(detection):
    ir = compile_detection(detection)
    out = compile_eql(ir)
    assert "sequence by actor.user_id, device.id with maxspan=45m" in out
    assert 'repository_sensitivity == "restricted"' in out
    assert "until [change_management.approval" in out
    assert ">= 8 occurrences within 15m" in out


def test_clickhouse_uses_window_funnel_and_countif(detection):
    out = compile_clickhouse(compile_detection(detection))
    assert "windowFunnel(2700)" in out
    assert "countIf(event_type = 'github.repository.clone'" in out
    assert ">= 8" in out
    assert "= 0" in out  # the suppressing exception


def test_kql_uses_scan(detection):
    out = compile_kql(compile_detection(detection))
    assert "scan with (" in out
    assert "partition by actor.user_id, device.id" in out


def test_spl_uses_transaction(detection):
    out = compile_spl(compile_detection(detection))
    assert "transaction actor_user_id device_id maxspan=2700s" in out
    assert "| where" in out


def test_all_registered_compilers_run(detection):
    ir = compile_detection(detection)
    for name, compiler in COMPILERS.items():
        rendered = compiler(ir)
        assert isinstance(rendered, str) and rendered.strip()
