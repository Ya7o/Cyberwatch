import csv
import json
from pathlib import Path

from cyberwatch.reset_baseline import audit, build_baseline


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _dataset(tmp_path: Path) -> Path:
    data = tmp_path / "data"
    _write_csv(
        data / "items.csv",
        ["Item_ID", "Source_ID", "Threat", "Sector", "Location"],
        [
            {"Item_ID": "I1", "Source_ID": "S1", "Threat": "Ransomware", "Sector": "Santé", "Location": "France"},
            {"Item_ID": "I2", "Source_ID": "S1", "Threat": "Inconnu", "Sector": "Inconnu", "Location": "France"},
        ],
    )
    _write_csv(
        data / "incidents.csv",
        ["Incident_ID", "Menace", "Secteur", "Localisation", "Items_Count"],
        [{"Incident_ID": "INC1", "Menace": "Ransomware", "Secteur": "Santé", "Localisation": "France", "Items_Count": 2}],
    )
    _write_csv(
        data / "run_log.csv",
        ["Run_ID", "As_Of", "Mode", "Target_Start", "Target_End", "Overall_Status", "Duration_s", "Requests"],
        [{"Run_ID": "RUN1", "As_Of": "2026-08-21", "Mode": "create", "Target_Start": "2026-01-01", "Target_End": "2026-08-21", "Overall_Status": "OK", "Duration_s": "90", "Requests": "10"}],
    )
    _write_csv(
        data / "run_sources.csv",
        ["Run_ID", "Source_ID", "Status", "Coverage", "Items_collected", "New_items", "Duration_s", "Collect_Duration_s", "Processing_Duration_s"],
        [{"Run_ID": "RUN1", "Source_ID": "S1", "Status": "OK", "Coverage": "FULL", "Items_collected": "2", "New_items": "2", "Duration_s": "30", "Collect_Duration_s": "20", "Processing_Duration_s": "10"}],
    )
    (data / "llm_usage.json").write_text(json.dumps({"calls_attempted": 2, "calls_succeeded": 2, "calls_failed": 0, "estimated_cost_usd": 0.01, "duration_seconds": 4, "total_tokens": 50, "by_task": {}}), encoding="utf-8")
    return data


def test_build_baseline_measures_volume_coverage_sources_and_llm(tmp_path: Path) -> None:
    baseline = build_baseline(_dataset(tmp_path))

    assert baseline["volume"]["items"] == 2
    assert baseline["volume"]["incidents"] == 1
    assert baseline["item_coverage"]["threat"]["known_pct"] == 50.0
    assert baseline["sources"]["S1"]["status"] == "OK"
    assert baseline["sources"]["S1"]["items"] == 2
    assert baseline["llm"]["estimated_cost_usd"] == 0.01


def test_audit_blocks_integrity_failures(tmp_path: Path) -> None:
    data = _dataset(tmp_path)
    rows = [
        {"Item_ID": "I1", "Source_ID": "S1", "Threat": "Ransomware", "Sector": "Santé", "Location": "France"},
        {"Item_ID": "I1", "Source_ID": "S1", "Threat": "Ransomware", "Sector": "Santé", "Location": "France"},
    ]
    _write_csv(data / "items.csv", ["Item_ID", "Source_ID", "Threat", "Sector", "Location"], rows)

    result = audit(build_baseline(data))

    assert result["verdict"] == "NO-GO"
    assert "Item_ID dupliqués" in result["blockers"]


def test_audit_warns_on_large_regression_without_turning_it_into_false_blocker(tmp_path: Path) -> None:
    after = build_baseline(_dataset(tmp_path))
    before = json.loads(json.dumps(after))
    before["volume"]["items"] = 10
    before["volume"]["incidents"] = 5
    before["item_coverage"]["sector"]["known_pct"] = 90.0

    result = audit(after, before)

    assert result["verdict"] == "GO"
    assert any("volume items" in warning for warning in result["warnings"])
    assert any("couverture sector" in warning for warning in result["warnings"])
