"""Régressions de bout en bout issues de l'audit de qualification 2026-09-06."""
from __future__ import annotations

import json

from cyberwatch import config, dedup, enrichment, runner, source_facts, sources
from cyberwatch.collectors.base import RawEntry
from cyberwatch.model import Item
from cyberwatch.normalize import classify_location
from cyberwatch.source_facts_ai_activity import normalize_activity


def _item(**values) -> Item:
    defaults = {
        "Item_ID": "audit",
        "Source_ID": "CYBERATTAQUE_ORG",
        "Organisation_Raw": "Acme",
        "Organisation_Key": "acme",
        "Published_Date": "2026-09-06",
        "Collected_As_Of": "2026-09-06",
        "Title": "Acme victime d'une intrusion",
        "URL": "https://example.test/acme",
        "Sector": config.SECTOR_UNKNOWN,
        "Threat": config.THREAT_INTRUSION,
        "Location": config.LOC_INCONNU,
    }
    return Item(**{**defaults, **values})


def _finalize(monkeypatch, items, facts=None):
    monkeypatch.setattr(enrichment, "load_reference", lambda: {})
    monkeypatch.setattr(enrichment.store, "load_incident_id_registry", lambda: [])
    monkeypatch.setattr(enrichment.store, "load_incident_dedup_registry", lambda: [])
    return enrichment.finalize_snapshot(items, facts or [], previous_sector_rows=[])


def test_negated_threats_remain_negative_through_finalization(monkeypatch):
    for title in (
        "Acme : intrusion dans la messagerie, aucune fuite de données identifiée",
        "Acme : intrusion confirmée, aucun ransomware détecté",
    ):
        report = _finalize(monkeypatch, [_item(Title=title)])
        assert report.incidents[0].Menace == config.THREAT_INTRUSION

    fact = {
        "Item_ID": "audit",
        "Summary": "Acme confirme une intrusion, mais aucune fuite de données.",
        "Data_Types_JSON": json.dumps(["adresses e-mail"]),
        "Claim_Status": "confirmed",
    }
    report = _finalize(monkeypatch, [_item()], [fact])
    assert report.incidents[0].Menace == config.THREAT_INTRUSION


def test_joigny_denial_cannot_publish_ransomware(monkeypatch):
    fact = {
        "Item_ID": "audit",
        "Summary": "La collectivité a repoussé 268 795 tentatives d'intrusion.",
        "Impact": (
            "La collectivité n’indique pas non plus avoir subi de chiffrement "
            "de ses serveurs, d’interruption majeure de ses services ou de "
            "demande de rançon."
        ),
        "Claim_Status": "confirmed",
    }
    item = _item(
        Title="Ville de Joigny : 268 795 tentatives d’intrusion en une semaine",
        Threat=config.THREAT_RANSOMWARE,
    )
    decision = _finalize(monkeypatch, [item], [fact]).incidents[0]
    assert decision.Menace == config.THREAT_INTRUSION


def test_aqualter_explicit_claimed_leak_beats_generic_cyberattack(monkeypatch):
    fact = {
        "Item_ID": "audit",
        "Summary": (
            "Une fuite revendiquée expose 187 073 numéros de téléphone et "
            "86 156 adresses e-mail liées à Aqualter."
        ),
        "Claim_Status": "claimed",
    }
    item = _item(
        Title="Aqualter : 187 000 numéros de téléphone exposés après une cyberattaque",
        Threat=config.THREAT_INTRUSION,
    )
    assert _finalize(monkeypatch, [item], [fact]).incidents[0].Menace == config.THREAT_LEAK


def test_accepted_threat_candidate_participates_in_final_decision(monkeypatch):
    fact = {
        "Item_ID": "audit",
        "Claim_Status": "reported",
        "Source_Metadata_JSON": json.dumps({
            "_source_facts_semantic_status": {"threat_candidate": "accepted"},
            "threat_tentative": {
                "value": config.THREAT_INTRUSION,
                "confidence": 0.9,
                "evidence": "Une faille a permis un accès non autorisé à l'infrastructure.",
            },
        }),
    }
    item = _item(Title="Acme signale un incident de sécurité", Threat=config.THREAT_LEAK)
    assert _finalize(monkeypatch, [item], [fact]).incidents[0].Menace == config.THREAT_INTRUSION


def test_specific_summary_threat_beats_feed_default(monkeypatch):
    entry = RawEntry(
        title="Acme",
        organisation="Acme",
        published="2026-09-06",
        summary="Acme est victime d'un ransomware avec exfiltration de données.",
        threat=config.THREAT_LEAK,
        url="https://example.test/acme",
    )
    item = runner.entry_to_item(
        entry, sources.by_id("FRENCHBREACHES"), "2026-09-06", {}, {}, {}, {}
    )
    assert item is not None and item.Threat == config.THREAT_RANSOMWARE
    facts = [{"Item_ID": item.Item_ID, "Summary": entry.summary, "Claim_Status": "reported"}]
    assert _finalize(monkeypatch, [item], facts).incidents[0].Menace == config.THREAT_RANSOMWARE


def test_initial_access_is_not_promoted_to_primary_threat(monkeypatch):
    facts = [{
        "Item_ID": "audit",
        "Summary": "Acme confirme une intrusion dans son système d'information.",
        "Initial_Access": "phishing",
        "Claim_Status": "confirmed",
    }]
    report = _finalize(monkeypatch, [_item()], facts)
    assert report.incidents[0].Menace == config.THREAT_INTRUSION


def test_location_ignores_third_party_clause_and_bare_counts():
    assert classify_location(
        "Acme : intrusion en France métropolitaine ; son prestataire est à La Réunion."
    ) == config.LOC_FRANCE
    assert classify_location("Acme : fuite de 97400 comptes clients") == config.LOC_INCONNU


def test_fine_location_evidence_overrides_source_default(monkeypatch):
    fact = {
        "Item_ID": "audit",
        "Fine_Location": "Saint-Denis de La Réunion",
        "Evidence_JSON": json.dumps(
            {"Fine_Location": "L'incident Acme touche le site de Saint-Denis de La Réunion."}
        ),
    }
    report = _finalize(
        monkeypatch,
        [_item(Source_ID="FRENCHBREACHES", Location=config.LOC_FRANCE)],
        [fact],
    )
    assert report.incidents[0].Localisation == config.LOC_REUNION


def test_location_conflict_abstains_instead_of_lexical_tie():
    items = [
        _item(Item_ID="a", Source_ID="FRENCHBREACHES", Location=config.LOC_FRANCE),
        _item(
            Item_ID="b",
            Source_ID="BONJOURLAFUITE",
            Location=config.LOC_MAYOTTE,
            URL="https://example.test/acme-2",
        ),
    ]
    assert dedup.build_incidents(items)[0].Localisation == config.LOC_INCONNU


def test_activity_semantics_cannot_contradict_literal_evidence(monkeypatch):
    context = "Acme commercialise en ligne des chaussures."
    raw = {
        "activity_description": {
            "value": "éditeur de logiciels",
            "confidence": 0.95,
            "evidence": context,
        },
        "activity_sector_match": {
            "value": config.SECTOR_TECH,
            "confidence": 0.95,
            "evidence": context,
        },
    }
    normalized, reasons = normalize_activity(raw, context, "Acme")
    assert "activity_sector_match" not in normalized
    assert reasons["activity_sector_match"] == "SECTOR_CONTRADICTS_ACTIVITY_EVIDENCE"
    fact = {
        "Item_ID": "audit",
        "Activity_Description": normalized["activity_description"]["value"],
        "Evidence_JSON": json.dumps(
            {"Activity_Description": normalized["activity_description"]["evidence"]}
        ),
    }
    assert _finalize(monkeypatch, [_item()], [fact]).incidents[0].Secteur == config.SECTOR_RETAIL


def test_rejected_activity_keeps_independent_native_sector(monkeypatch):
    fact = {
        "Item_ID": "audit",
        "Source_Sector_Raw": "Manufacturing",
        "Activity_Description": "éditeur de logiciels",
        "Activity_Sector_Match": config.SECTOR_TECH,
        "Evidence_JSON": json.dumps(
            {"Activity_Description": "Le fournisseur AcmeSoft édite des logiciels."}
        ),
    }
    report = _finalize(monkeypatch, [_item(Sector=config.SECTOR_INDUSTRY)], [fact])
    assert report.incidents[0].Secteur == config.SECTOR_INDUSTRY
    assert report.sector_resolution_rows[0]["Reason"] == "SOURCE_SECTOR_RAW"


def test_second_abstention_clears_activity_from_changed_content():
    old = {
        "Item_ID": "audit",
        "Activity_Description": "vente en ligne de chaussures",
        "Activity_Sector_Match": config.SECTOR_RETAIL,
        "Evidence_JSON": json.dumps(
            {"Activity_Description": "Acme commercialise en ligne des chaussures."}
        ),
        "Source_Metadata_JSON": json.dumps({"_source_facts_content_hash": "A"}),
    }

    def revision(status):
        return {
            "Item_ID": "audit",
            "Activity_Description": "",
            "Activity_Sector_Match": "",
            "Source_Metadata_JSON": json.dumps(
                {
                    "_source_facts_content_hash": "B",
                    "_source_facts_semantic_status": {
                        "activity_description": status,
                        "activity_sector_match": status,
                    },
                }
            ),
        }

    first = source_facts.merge_source_facts([old], [revision("miss")])
    assert first[0]["Activity_Description"]
    second = source_facts.merge_source_facts(first, [revision("abstained")])
    assert second[0]["Activity_Description"] == ""
    assert second[0]["Activity_Sector_Match"] == ""
