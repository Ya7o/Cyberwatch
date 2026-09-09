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
    assert sf._activity_evidence_matches_organisation(
        "SDIS de la Moselle",
        "Le service départemental d’incendie et de secours de la Moselle intervient.",
    )
    assert not sf._activity_evidence_matches_organisation(
        "SDIS de la Moselle",
        "Le département de la Moselle accompagne ses services publics.",
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


def test_materialization_gap_detecte_une_valeur_accepted_perdue_dans_le_csv():
    fact = {
        "Item_ID": "ITM-qare",
        "Activity_Description": "",
        "Activity_Sector_Match": "",
        "Source_Metadata_JSON": sf._dumps_json({
            "_source_facts_semantic_status": {
                "activity_description": "accepted",
                "activity_sector_match": "accepted",
                "attack_date": "abstained",
            }
        }),
    }
    assert sf.semantic_materialization_gaps([fact]) == [
        "ITM-qare:activity_description",
        "ITM-qare:activity_sector_match",
    ]


def test_materialization_gap_ignore_une_suppression_editoriale_tracee():
    fact = {
        "Item_ID": "ITM-audit",
        "Impact": "",
        "Source_Metadata_JSON": sf._dumps_json({
            "_source_facts_semantic_status": {"impact": "accepted"},
            "editorial_correction": {
                "audit": "AUDIT-X",
                "reason": "Le texte décrit seulement un risque futur.",
                "suppressed_semantic_fields": ["impact"],
            },
        }),
    }
    assert sf.semantic_materialization_gaps([fact]) == []


def test_materialise_cache_borne_par_item_et_hash():
    fact = {
        "Item_ID": "ITM-qare",
        "Activity_Description": "",
        "Activity_Sector_Match": "",
        "Evidence_JSON": "{}",
        "Source_Metadata_JSON": sf._dumps_json({
            "_source_facts_content_hash": "hash-qare",
            "_source_facts_semantic_status": {
                "activity_description": "accepted",
                "activity_sector_match": "accepted",
            },
        }),
    }
    hydrated, changed = sf.materialize_cached_llm_fields([fact], [{
        "item_id": "ITM-qare",
        "content_hash": "hash-qare",
        "fields": {
            "activity_description": {
                "status": "accepted",
                "version": sfa.FIELD_VERSIONS["activity_description"],
                "value": {"value": "téléconsultation", "evidence": "plateforme de téléconsultation"},
            },
            "activity_sector_match": {
                "status": "accepted",
                "version": sfa.FIELD_VERSIONS["activity_sector_match"],
                "value": {"value": "Santé", "evidence": "plateforme de téléconsultation médicale"},
            },
        },
    }])
    assert changed == ["ITM-qare"]
    assert hydrated[0]["Activity_Description"] == "téléconsultation"
    assert hydrated[0]["Activity_Sector_Match"] == "Santé"
    assert sf.semantic_materialization_gaps(hydrated) == []


def test_materialise_cache_ignore_un_contrat_llm_obsolete():
    fact = {
        "Item_ID": "ITM-old",
        "Evidence_JSON": "{}",
        "Source_Metadata_JSON": sf._dumps_json({
            "_source_facts_content_hash": "hash-old",
            "_source_facts_semantic_status": {"threat_candidate": "accepted"},
        }),
    }
    hydrated, changed = sf.materialize_cached_llm_fields([fact], [{
        "item_id": "ITM-old",
        "content_hash": "hash-old",
        "fields": {
            "threat_candidate": {
                "status": "accepted",
                "version": "threat-candidate-v1",
                "value": {
                    "value": "Malware",
                    "evidence": "La victime indique avoir subi un piratage.",
                },
            },
        },
    }])
    metadata = sf._loads_json(hydrated[0]["Source_Metadata_JSON"])
    assert changed == ["ITM-old"]
    assert "threat_tentative" not in metadata
    assert metadata["_source_facts_semantic_status"]["threat_candidate"] == "stale_contract"
    assert metadata["_source_facts_stale_contracts"] == ["threat_candidate"]


def test_historical_accepted_marker_follows_rejected_cache_contract():
    fact = {
        "Item_ID": "ITM-history",
        "Source_Metadata_JSON": sf._dumps_json({
            "_source_facts_content_hash": "same-content",
            "_source_facts_semantic_status": {"threat_candidate": "accepted"},
        }),
    }
    hydrated, changed = sf.materialize_cached_llm_fields([fact], [{
        "item_id": "ITM-history", "content_hash": "same-content",
        "fields": {"threat_candidate": {
            "status": "rejected_validation",
            "version": sfa.FIELD_VERSIONS["threat_candidate"],
            "value": None,
        }},
    }])
    metadata = sf._loads_json(hydrated[0]["Source_Metadata_JSON"])
    assert changed == ["ITM-history"]
    assert metadata["_source_facts_semantic_status"]["threat_candidate"] == "cache_not_accepted"
    assert not metadata.get("threat_tentative")
    assert sf.semantic_materialization_gaps(hydrated) == []
