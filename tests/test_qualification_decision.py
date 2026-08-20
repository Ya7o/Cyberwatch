from cyberwatch import config
from cyberwatch.qualification import stabilize_threats
from cyberwatch.qualification_decision import (
    QualificationDecision,
    decisions_from_provenance,
    record_mutations,
    snapshot_fields,
    summarize_decisions,
)


def test_record_mutations_captures_field_origin(make_item):
    item = make_item(sector=config.SECTOR_UNKNOWN, location=config.LOC_INCONNU)
    before = snapshot_fields([item])
    item.Sector = config.SECTOR_HEALTH
    decisions = record_mutations(before, [item], origin="STRUCTURED_SOURCE", confidence="HIGH")
    assert decisions == [QualificationDecision(
        item_id=item.Item_ID, source_id=item.Source_ID, field="Sector",
        previous_value=config.SECTOR_UNKNOWN, candidate_value=config.SECTOR_HEALTH,
        final_value=config.SECTOR_HEALTH, origin="STRUCTURED_SOURCE", confidence="HIGH",
    )]


def test_decisions_from_provenance_preserves_rejection():
    rows = [{
        "Item_ID": "ITEM-1", "Source_ID": "CYBERATTAQUE_ORG", "Field": "Sector",
        "Previous_Value": config.SECTOR_UNKNOWN, "Candidate_Value": config.SECTOR_HEALTH,
        "Final_Value": config.SECTOR_UNKNOWN, "Origin": "LLM_SOURCE_FALLBACK",
        "Confidence": "", "Evidence": "official evidence", "Match_Strategy": "source_url",
        "Decision": "REJECTED_POLICY_DISABLED",
    }]
    decision = decisions_from_provenance(rows)[0]
    assert decision.decision == "REJECTED_POLICY_DISABLED"
    assert decision.candidate_value == config.SECTOR_HEALTH
    assert decision.final_value == config.SECTOR_UNKNOWN


def test_summary_groups_by_origin_and_field():
    decisions = [
        QualificationDecision("ITEM-1", "A", "Sector", "Inconnu", "Santé", "Santé", "MANUAL_REFERENCE", "HIGH"),
        QualificationDecision("ITEM-2", "A", "Sector", "Inconnu", "Industrie", "Inconnu", "LLM_SOURCE_FALLBACK", "", decision="REJECTED_POLICY_DISABLED"),
        QualificationDecision("ITEM-3", "A", "Threat", "Inconnu", "Ransomware", "Inconnu", "LLM_SOURCE_FALLBACK", "", decision="PROTECTED"),
    ]
    by_key = {(row["Origin"], row["Field"]): row for row in summarize_decisions(decisions)}
    assert by_key[("MANUAL_REFERENCE", "Sector")]["Applied"] == 1
    assert by_key[("LLM_SOURCE_FALLBACK", "Sector")]["Rejected"] == 1
    assert by_key[("LLM_SOURCE_FALLBACK", "Threat")]["Protected"] == 1


def test_threat_stabilization_can_be_observed(make_item):
    item = make_item(source="RANSOMWARE_LIVE", threat=config.THREAT_UNKNOWN)
    before = snapshot_fields([item])
    assert stabilize_threats([item]) == 1
    decisions = record_mutations(before, [item], origin="THREAT_STABILIZATION", confidence="HIGH")
    assert item.Threat == config.THREAT_RANSOMWARE
    assert len(decisions) == 1
    assert decisions[0].field == "Threat"
    assert decisions[0].origin == "THREAT_STABILIZATION"
