from cyberwatch.qualification_decision import QualificationDecision
from cyberwatch.qualification_quality import evaluate_decisions_by_origin

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
