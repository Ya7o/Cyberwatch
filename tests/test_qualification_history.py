from cyberwatch.qualification_history import detect_source_drift, history_rows

def test_history_rows_keeps_source_coverage_and_field_decisions():
    report = {"coverage":[{"Source_ID":"SRC","Field":"Sector","Total":10,"Known":8,"Unknown":2,"Coverage_pct":80.0}],
              "decision_summary":[{"Origin":"A","Field":"Sector","Decisions":3,"Applied":2,"Rejected":1,"Protected":0}, {"Origin":"B","Field":"Sector","Decisions":2,"Applied":1,"Rejected":0,"Protected":1}]}
    row = history_rows(report, run_id="RUN-1", recorded_at="2026-08-20T00:00:00+00:00")[0]
    assert row["Source_ID"] == "SRC" and row["Decisions"] == 5 and row["Applied"] == 3 and row["Rejected"] == 1

def test_detect_source_drift_uses_own_recent_baseline():
    history = [{"Run_ID":f"R{i}","Source_ID":"SRC","Field":"Sector","Coverage_pct":90.0,"Unknown":10} for i in range(5)]
    current = [{"Run_ID":"R6","Source_ID":"SRC","Field":"Sector","Coverage_pct":86.0,"Unknown":14}]
    alerts = detect_source_drift(current, history)
    assert len(alerts) == 1
    assert "coverage_drop=4.0pp" in alerts[0]["Reasons"] and "unknown_growth=40.0%" in alerts[0]["Reasons"]

def test_detect_source_drift_ignores_small_noise():
    history = [{"Run_ID":"R1","Source_ID":"SMALL","Field":"Location","Coverage_pct":80.0,"Unknown":1}]
    current = [{"Run_ID":"R2","Source_ID":"SMALL","Field":"Location","Coverage_pct":79.5,"Unknown":2}]
    assert detect_source_drift(current, history) == []
