import subprocess
import sys
from pathlib import Path

from cyberwatch import ai, company_evidence, model, org_enrichment, status


def test_run_source_columns_include_performance_breakdown():
    expected = {
        "Collect_Duration_s", "Processing_Duration_s",
        "Org_Registry_Duration_s", "Org_Official_Site_Duration_s",
        "Qualification_LLM_Duration_s", "SourceFacts_LLM_Duration_s",
        "Other_Processing_Duration_s",
    }
    assert expected <= set(model.RUN_SOURCE_COLUMNS)
    outcome = status.SourceOutcome("X", "CORE_DIRECT")
    assert outcome.collect_duration_seconds == 0.0
    assert outcome.qualification_llm_calls == 0


def test_official_site_fallback_is_timed(monkeypatch):
    ticks = iter([10.0, 12.5])
    monkeypatch.setattr(org_enrichment.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(company_evidence, "resolve_official_site", lambda _name: None)
    state = org_enrichment.OrgEnrichmentState(enabled=True)
    attempted, record = org_enrichment._official_site_fallback("x", "Example", "now", state)
    assert attempted is True
    assert record is None
    assert state.official_site_attempted == 1
    assert state.official_site_duration_seconds == 2.5


def test_qualification_openai_network_time_is_timed(monkeypatch):
    class Response:
        status_code = 200
        text = ""

        def json(self):
            return {"ok": True}

    ticks = iter([5.0, 7.0])
    monkeypatch.setattr(ai.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(ai.requests, "post", lambda *args, **kwargs: Response())
    state = ai.AiRunState(enabled=True, api_key="test")
    assert ai._post_openai({}, state) == {"ok": True}
    assert state.llm_duration_seconds == 2.0


def test_report_script_runs_from_repo_root():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "scripts/report_source_performance.py"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "SOURCE_PERF" in result.stdout
