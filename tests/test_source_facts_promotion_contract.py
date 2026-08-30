from __future__ import annotations

from cyberwatch import source_facts as sf
from cyberwatch import source_facts_ai as sfa


def test_activity_evidence_accepts_editorial_variant_of_victim_name():
    assert sf._activity_evidence_matches_organisation(
        "CGT Éduc’Action Créteil",
        "La CGT Éduc’Action de l’académie de Créteil représente les personnels de l'éducation.",
    )
    assert sf._activity_evidence_matches_organisation(
        "SDIS de la Moselle",
        "Le SDIS 57 est le service départemental d’incendie et de secours de la Moselle.",
    )
    assert not sf._activity_evidence_matches_organisation(
        "SDIS de la Moselle",
        "Une entreprise spécialisée dans les services informatiques.",
    )


def test_semantic_promotion_gap_couvre_activity_sector_match():
    semantic = sfa.SemanticExtraction(
        item_id="ITM-x",
        content_hash="hash",
        fields={
            "activity_description": {"value": "organisation syndicale", "evidence": "CGT, organisation syndicale"},
            "activity_sector_match": {"value": "Association / Syndicat", "evidence": "CGT, organisation syndicale"},
        },
        statuses={"activity_description": "accepted", "activity_sector_match": "accepted"},
    )
    fact = {"Activity_Description": "organisation syndicale", "Activity_Sector_Match": "", "Source_Metadata_JSON": ""}
    assert sf.semantic_promotion_gaps(fact, semantic) == ["activity_sector_match"]


def test_merge_can_clear_stale_activity_after_semantic_abstention():
    old = [{
        "Item_ID": "ITM-x",
        "Activity_Description": "ancienne activité",
        "Activity_Sector_Match": "Services aux entreprises",
        "Source_Metadata_JSON": sf._dumps_json({"_source_facts_content_hash": "old"}),
    }]
    new = [{
        "Item_ID": "ITM-x",
        "Source_Metadata_JSON": sf._dumps_json({
            "_source_facts_content_hash": "new",
            "_source_facts_semantic_status": {
                "activity_description": "abstained",
                "activity_sector_match": "abstained",
            },
        }),
    }]
    merged = sf.merge_source_facts(old, new)[0]
    assert merged["Activity_Description"] == ""
    assert merged["Activity_Sector_Match"] == ""
