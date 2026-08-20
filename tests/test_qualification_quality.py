from cyberwatch.qualification_decision import QualificationDecision
from cyberwatch.qualification_quality import evaluate_decisions_by_origin, quality_gate_failures


def test_quality_by_origin_counts_gain_and_regression():
    decisions = [
        QualificationDecision("1","SRC","Sector","Inconnu","Santé","Santé","STRUCTURED_SOURCE","HIGH"),
        QualificationDecision("2","SRC","Sector","Commerce / Distribution","Santé","Santé","STRUCTURED_SOURCE","HIGH"),
        QualificationDecision("3","SRC","Sector","Santé","Commerce / Distribution","Commerce / Distribution","SAFE_NAME_RULE","HIGH"),
        QualificationDecision("4","SRC","Sector","Inconnu","Santé","Inconnu","LLM_SOURCE_FALLBACK","",decision="REJECTED_POLICY_DISABLED"),
    ]
    refs = {
        "1":{"Secteur_REF":"Santé"}, "2":{"Secteur_REF":"Industrie"},
        "3":{"Secteur_REF":"Santé"}, "4":{"Secteur_REF":"Santé"},
    }
    rows = evaluate_decisions_by_origin(decisions, refs)
    by_origin = {row["Origin"]: row for row in rows}
    assert by_origin["STRUCTURED_SOURCE"]["Correct"] == 1
    assert by_origin["STRUCTURED_SOURCE"]["Incorrect"] == 1
    assert by_origin["STRUCTURED_SOURCE"]["Gains"] == 1
    assert by_origin["SAFE_NAME_RULE"]["Regressions"] == 1
    assert by_origin["LLM_SOURCE_FALLBACK"]["Abstentions"] == 1


def test_quality_ignores_items_without_reference():
    decision = QualificationDecision("missing","SRC","Threat","Inconnu","Ransomware","Ransomware","THREAT_STABILIZATION","HIGH")
    assert evaluate_decisions_by_origin([decision], {}) == []


def test_quality_gate_ignores_small_samples_until_baseline_is_sufficient():
    rows = [{"Origin":"STRUCTURED_SOURCE","Field":"Sector","Applied":9,"Precision_pct":55.0,"Regressions":3}]
    assert quality_gate_failures(rows, minimum_cases=10) == []


def test_quality_gate_reports_precision_and_regressions():
    rows = [{"Origin":"STRUCTURED_SOURCE","Field":"Sector","Applied":20,"Precision_pct":90.0,"Regressions":2}]
    failures = quality_gate_failures(rows, minimum_cases=10, minimum_precision_pct=95.0, maximum_regressions=0)
    assert len(failures) == 2
    assert "precision 90.0% < 95.0%" in failures[0]
    assert "2 regression(s) > 0" in failures[1]


def test_quality_gate_accepts_homologated_channel():
    rows = [{"Origin":"MANUAL_REFERENCE","Field":"Sector","Applied":25,"Precision_pct":100.0,"Regressions":0}]
    assert quality_gate_failures(rows) == []
