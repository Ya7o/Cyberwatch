from cyberwatch import incremental, incremental_runtime
from cyberwatch.incremental import DirtySet
from cyberwatch.performance_gates import validate_performance_row


def test_delta_is_forbidden_when_prequalification_has_work():
    errors = validate_performance_row({
        "qualification_mode": "delta",
        "prequal_new": 1,
        "prequal_dirty": 0,
        "sourcefacts_llm_calls": 0,
    })
    assert any("delta_with_work" in error for error in errors)


def test_delta_is_forbidden_with_sourcefacts_llm():
    errors = validate_performance_row({
        "qualification_mode": "delta",
        "prequal_new": 0,
        "prequal_dirty": 0,
        "sourcefacts_llm_calls": 1,
    })
    assert "delta_with_sourcefacts_llm" in errors


def test_clean_delta_row_passes():
    assert validate_performance_row({
        "qualification_mode": "delta",
        "prequal_new": 0,
        "prequal_dirty": 0,
        "sourcefacts_llm_calls": 0,
        "shadow_mismatches": 0,
    }) == []


def test_runtime_dirty_set_contract_exposes_work_items(monkeypatch):
    dirty = DirtySet(("NEW",), ("DIRTY",), ("UNCHANGED",), {})
    assert dirty.work_item_ids == ("NEW", "DIRTY")


def test_incremental_runtime_remains_opt_in(monkeypatch):
    monkeypatch.delenv("CYBERWATCH_INCREMENTAL_QUALIFICATION", raising=False)
    assert incremental_runtime.enabled() is False


def test_qualification_policy_is_part_of_incremental_dependency_digest():
    assert "qualification_policy.py" in incremental.QUALIFICATION_CODE_FILES
