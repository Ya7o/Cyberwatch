from pathlib import Path

from cyberwatch import config
from cyberwatch.golden import read_csv
from cyberwatch.golden_review import apply_audit, quality_report, validate_audit

ROOT = Path(__file__).resolve().parents[1]


def _golden(golden_id="GOLD-0001", **overrides):
    row = {
        "Golden_ID": golden_id,
        "Organisation": "Centre Exemple",
        "Organisation_Key": "centre exemple",
        "Reference_Date": "2026-06-01",
        "Source_IDs": "CYBERATTAQUE_ORG",
        "Source_URLs": "https://example.test/case",
        "Secteur_REF": config.SECTOR_HEALTH,
        "Menace_REF": config.THREAT_INTRUSION,
        "Localisation_REF": config.LOC_FRANCE,
        "Secteur_Confidence": "HIGH",
        "Menace_Confidence": "HIGH",
        "Localisation_Confidence": "HIGH",
        "Secteur_Evidence": "activité de santé explicitement décrite",
        "Menace_Evidence": "accès non autorisé au système",
        "Localisation_Evidence": "implantation française explicitement décrite",
        "Incident_ID_Snapshot": "INC-OLD",
        "Reviewed_At": "2026-08-16",
        "Golden_Version": "1",
        "Taxonomy_Version": config.METHOD_ID,
    }
    row.update(overrides)
    return row


def _audit(golden_id="GOLD-0001", **overrides):
    row = {
        "Golden_ID": golden_id,
        "Field": "Menace",
        "Old_Value": config.THREAT_INTRUSION,
        "Proposed_Value": config.THREAT_LEAK,
        "Decision": "CORRECTED",
        "Confidence": "HIGH",
        "Evidence_URLs": "https://example.test/evidence",
        "Evidence_Text": "fuite de données confirmée",
        "Reason": "la fuite est une classe plus spécifique",
        "Reviewed_At": "2026-08-17",
    }
    row.update(overrides)
    return row


def test_repository_golden_audit_contract_is_valid():
    golden = read_csv(ROOT / "data" / "golden" / "qualification_golden.csv")
    audit = read_csv(ROOT / "data" / "golden" / "qualification_golden_audit.csv")
    assert validate_audit(audit, golden) == []


def test_audit_rejects_stale_old_value():
    problems = validate_audit([_audit(Old_Value=config.THREAT_RANSOMWARE)], [_golden()])
    assert any("Old_Value" in problem for problem in problems)


def test_apply_audit_corrects_label_and_versions_only_reviewed_case():
    rows = apply_audit([_golden()], [_audit()])
    assert rows[0]["Menace_REF"] == config.THREAT_LEAK
    assert rows[0]["Menace_Evidence"] == "fuite de données confirmée"
    assert rows[0]["Golden_Version"] == "2"
    assert rows[0]["Reviewed_At"] == "2026-08-17"


def test_apply_audit_removes_duplicate_without_mutating_canonical_target():
    duplicate = _golden("GOLD-0001", Reference_Date="2026-06-01")
    canonical = _golden("GOLD-0002", Reference_Date="2026-06-02", Incident_ID_Snapshot="INC-2")
    audit = _audit(
        Decision="DUPLICATE",
        Field="Incident",
        Old_Value="",
        Proposed_Value="GOLD-0002",
        Confidence="HIGH",
        Evidence_Text="",
    )
    rows = apply_audit([duplicate, canonical], [audit])
    assert [row["Golden_ID"] for row in rows] == ["GOLD-0002"]
    assert rows[0]["Golden_Version"] == "1"


def test_apply_audit_excludes_unresolved_review_from_benchmark_view():
    unresolved = _golden("GOLD-0001")
    stable = _golden("GOLD-0002", Reference_Date="2026-07-01", Incident_ID_Snapshot="INC-2")
    review = _audit(
        Decision="REVIEW",
        Field="Incident",
        Old_Value="",
        Proposed_Value="",
        Confidence="MEDIUM",
        Evidence_Text="",
    )
    rows = apply_audit([unresolved, stable], [review])
    assert [row["Golden_ID"] for row in rows] == ["GOLD-0002"]


def test_quality_report_flags_high_without_url_and_close_duplicate():
    left = _golden(Source_URLs="")
    right = _golden("GOLD-0002", Reference_Date="2026-06-03", Incident_ID_Snapshot="INC-2")
    report = quality_report([left, right])
    codes = {finding["Code"] for finding in report["findings"]}
    assert "HIGH_WITHOUT_SOURCE_URL" in codes
    assert "POSSIBLE_DUPLICATE" in codes
    assert report["possible_duplicate_pairs"] == 1


def test_quality_report_applies_corrections_before_policy_checks():
    row = _golden(Menace_Evidence="fuite de données confirmée")
    before = quality_report([row])
    assert any(finding["Code"] == "THREAT_POLICY_MISMATCH" for finding in before["findings"])

    after = quality_report([row], [_audit(Evidence_Text="fuite de données confirmée")])
    assert not any(finding["Code"] == "THREAT_POLICY_MISMATCH" for finding in after["findings"])
