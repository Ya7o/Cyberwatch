from cyberwatch import config
from cyberwatch.qualification import stabilize_threats
from cyberwatch.qualification_decision import QualificationDecision, ORIGIN_PRIORITY, decisions_from_provenance, precedence, record_mutations, snapshot_fields, summarize_decisions

def test_record_mutations_captures_field_origin(make_item):
    item = make_item(sector=config.SECTOR_UNKNOWN, location=config.LOC_INCONNU); before = snapshot_fields([item]); item.Sector = config.SECTOR_HEALTH
    decisions = record_mutations(before, [item], origin="STRUCTURED_SOURCE", confidence="HIGH")
    assert decisions[0].origin == "STRUCTURED_SOURCE" and decisions[0].field == "Sector"
    assert decisions[0].previous_value == config.SECTOR_UNKNOWN and decisions[0].final_value == config.SECTOR_HEALTH

def test_decisions_from_provenance_preserves_rejection():
    rows = [{"Item_ID":"ITEM-1","Source_ID":"CYBERATTAQUE_ORG","Field":"Sector","Previous_Value":config.SECTOR_UNKNOWN,"Candidate_Value":config.SECTOR_HEALTH,"Final_Value":config.SECTOR_UNKNOWN,"Origin":"LLM_SOURCE_FALLBACK","Confidence":"","Evidence":"official","Match_Strategy":"source_url","Decision":"REJECTED_POLICY_DISABLED"}]
    decision = decisions_from_provenance(rows)[0]
    assert decision.decision == "REJECTED_POLICY_DISABLED" and decision.candidate_value == config.SECTOR_HEALTH

def test_summary_groups_by_origin_and_field():
    decisions = [QualificationDecision("1","A","Sector","Inconnu","Santé","Santé","MANUAL_REFERENCE","HIGH"), QualificationDecision("2","A","Sector","Inconnu","Industrie","Inconnu","LLM_SOURCE_FALLBACK","",decision="REJECTED_POLICY_DISABLED")]
    by_key = {(row["Origin"], row["Field"]): row for row in summarize_decisions(decisions)}
    assert by_key[("MANUAL_REFERENCE","Sector")]["Applied"] == 1
    assert by_key[("LLM_SOURCE_FALLBACK","Sector")]["Rejected"] == 1

def test_threat_stabilization_can_be_observed(make_item):
    item = make_item(source="RANSOMWARE_LIVE", threat=config.THREAT_UNKNOWN); before = snapshot_fields([item])
    assert stabilize_threats([item]) == 1
    decisions = record_mutations(before, [item], origin="THREAT_STABILIZATION", confidence="HIGH")
    assert item.Threat == config.THREAT_RANSOMWARE and decisions[0].field == "Threat"

def test_precedence_contract_is_explicit_and_llm_is_last():
    assert precedence("SOURCE_NATIVE") < precedence("MANUAL_REFERENCE") < precedence("STRUCTURED_SOURCE")
    assert precedence("ORG_CONTEXT_SECTOR") < precedence("ORG_SECTOR_REGISTRY") < precedence("LLM_SOURCE_FALLBACK")
    assert precedence("LLM_SOURCE_FALLBACK") == max(ORIGIN_PRIORITY.values())
    assert precedence("UNKNOWN_FUTURE_CHANNEL") > precedence("LLM_SOURCE_FALLBACK")
