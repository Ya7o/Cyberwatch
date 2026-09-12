"""Replay BLF sans réseau, de la timeline aux décisions sectorielles."""
import json
from dataclasses import replace

import pytest
import requests

from cyberwatch import blf_org_enrichment as blf
from cyberwatch import config, org_identity, sector_resolution, sector_semantic, source_facts
from cyberwatch.collectors.base import SourceSpec
from cyberwatch.collectors.bonjourlafuite import parse_timeline
from cyberwatch.model import Item

TYPES = ["Nom, prénom", "Adresse postale", "Date de naissance", "Achats des titres"]
ACTIVITY = "PassPass est un service de vente de titres de transport."


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(requests.Session, "request", lambda *a, **k: pytest.fail("réseau interdit"))
    monkeypatch.setattr(org_identity, "ORGANISATION_IDENTITY_REGISTRY", {"pass pass": "passpass"})


@pytest.fixture
def replay():
    html = ('<p>12 septembre 2026</p><h2>🟢 Pass Pass</h2>'
            '<p>Données concernées :</p>' + ''.join(f'<span>{v}</span>' for v in TYPES)
            + '<a href="https://example.org/blf">Source</a>')
    entry = parse_timeline(html, "https://bonjourlafuite.eu.org/")[0]
    item = Item(Item_ID="ITM-blf", Source_ID=blf.BLF, Organisation_Raw="Pass Pass",
                Organisation_Key="pass pass", Published_Date="2026-09-12",
                Sector=config.SECTOR_UNKNOWN, Threat=config.THREAT_UNKNOWN, URL=entry.url)
    spec = SourceSpec(source_id=blf.BLF, layer="core", zone="France", start_url=entry.url)
    fact = source_facts.extract_source_fact(item, entry, spec)
    old = replace(item, Item_ID="ITM-history", Source_ID="FRENCHBREACHES",
                  Organisation_Raw="PassPass", Published_Date="2026-01-01",
                  URL="https://example.org/activity")
    old_fact = {"Item_ID": old.Item_ID, "Source_ID": old.Source_ID,
                "Activity_Description": ACTIVITY,
                "Evidence_JSON": json.dumps({"Activity_Description": ACTIVITY})}
    return item, fact, old, old_fact


def origin(fact):
    return blf.metadata(fact["Source_Metadata_JSON"])[blf.KEY]["origin"]


def test_pass_pass_activity_replay_and_withdrawal(replay):
    item, fact, old, old_fact = replay
    assert fact["Claim_Status"] == "confirmed"
    assert json.loads(fact["Data_Types_JSON"]) == TYPES
    assert "Pass Pass" in fact["Summary"]
    assert all(v in fact["Summary"] for v in TYPES)
    assert blf.enrich([item, old], [fact, old_fact]) == [item.Item_ID]
    first = dict(fact)
    assert blf.enrich([item, old], [fact, old_fact]) == [item.Item_ID]
    assert fact == first
    assert origin(fact) == "BLF_ACTIVITY_REUSE"
    assert sector_semantic.annotate_source_facts([item], [fact], {}) == []
    decision = sector_resolution.resolve_item(item, fact, {})
    assert decision.sector == "Transport / Logistique"
    assert decision.evidence == ACTIVITY and decision.evidence_url == old.URL
    sector_resolution.resolve_items([item], [fact], {})
    blf.enrich([item], [fact])
    assert not fact["Activity_Description"]
    assert sector_resolution.resolve_item(item, fact, {}).sector == config.SECTOR_UNKNOWN


def test_no_history_keeps_unknown_and_fills_legacy_summary(replay):
    item, fact, _, _ = replay
    fact["Summary"] = ""
    blf.enrich([item], [fact])
    assert fact["Summary"] and json.loads(fact["Data_Types_JSON"]) == TYPES
    assert origin(fact) == "BLF_NO_ACTIVITY_EVIDENCE"
    assert sector_resolution.resolve_item(item, fact, {}).reason == "NO_ACTIVITY_EVIDENCE"
    assert sector_semantic.gap(item, fact, {}) is None


@pytest.mark.parametrize("legacy", [False, True])
def test_publication_preserves_summary_bubbles_and_sensitivity(replay, legacy):
    from cyberwatch import data_sensitivity, fact_resolution, site_legacy
    item, fact, _, _ = replay
    if legacy:
        fact["Summary"] = "Données concernées : Nom, prénom, Adresse postale et Date de naissance."
    existing_summary = fact["Summary"]
    blf.enrich([item], [fact])
    assert fact["Summary"] == existing_summary
    detail = fact_resolution.resolve_incident_facts(
        [site_legacy._source_fact_payload(fact)], organisation=item.Organisation_Raw)
    assert detail["display_summary"]
    assert len(detail["data_types"]) == 4
    assert [value["value"] for value in detail["data_types"]] == [
        fact_resolution.canonical_data_type(value) for value in TYPES]
    assert all(value in " ".join(detail["summary_paragraphs"]) for value in TYPES)
    sensitivity = data_sensitivity.classify(detail)
    assert sensitivity["personal_data_exposed"]
    assert not sensitivity["credentials_or_secrets_exposed"]
    assert not sensitivity["high_sensitivity_data_exposed"]


@pytest.mark.parametrize("status,expected", [("claimed", "revendication"), ("unconfirmed", "non confirmée")])
def test_summary_certainty_and_preservation(replay, status, expected):
    item, fact, _, _ = replay
    fact.update(Summary="", Claim_Status=status)
    assert expected in blf.build_blf_summary(item, fact)
    fact["Summary"] = "Résumé existant."
    blf.enrich([item], [fact])
    assert fact["Summary"] == "Résumé existant."


def test_collection_merge_preserves_existing_blf_summary(replay):
    _, incoming, _, _ = replay
    existing = {**incoming, "Summary": "Résumé déjà présent.",
                "Evidence_JSON": json.dumps({"Summary": "Citation antérieure."})}
    merged = source_facts.merge_source_facts([existing], [incoming])[0]
    assert merged["Summary"] == existing["Summary"]
    assert json.loads(merged["Evidence_JSON"])["Summary"] == "Citation antérieure."


@pytest.mark.parametrize("field,value", [("Activity_Description", ""), ("Evidence_JSON", "{}"),
                                         ("Evidence_JSON", '{"Activity_Description":"Transport"}')])
def test_unsupported_history_never_becomes_activity(replay, field, value):
    item, fact, old, old_fact = replay
    old.Sector = "Transport / Logistique"
    old_fact[field] = value
    blf.enrich([item, old], [fact, old_fact])
    assert not fact.get("Activity_Description")
    assert origin(fact) == "BLF_NO_ACTIVITY_EVIDENCE"


def test_conflict_abstains_even_with_provider(replay):
    item, fact, old, old_fact = replay
    other = replace(old, Item_ID="ITM-other")
    activity = "PassPass est une entreprise spécialisée dans la fabrication de logiciels."
    other_fact = {**old_fact, "Item_ID": other.Item_ID, "Activity_Description": activity,
                  "Evidence_JSON": json.dumps({"Activity_Description": activity})}
    class Provider:
        def resolve(self, organisation):
            pytest.fail("Un conflit ne doit pas être contourné")
    blf.enrich([item, old, other], [fact, old_fact, other_fact], provider=Provider())
    assert origin(fact) == "BLF_ACTIVITY_CONFLICT"
    assert sector_resolution.resolve_item(item, fact, {}).reason == "BLF_ACTIVITY_CONFLICT"


def test_best_proof_then_recent_proof(replay):
    item, fact, old, old_fact = replay
    recent = replace(old, Item_ID="ITM-recent", Published_Date="2026-02-01")
    recent_fact = {**old_fact, "Item_ID": recent.Item_ID}
    blf.enrich([item, old, recent], [fact, old_fact, recent_fact])
    assert blf.metadata(fact["Source_Metadata_JSON"])[blf.KEY]["source_item_id"] == recent.Item_ID


@pytest.mark.parametrize("source", ["FRENCHBREACHES", "CYBERATTAQUE_ORG", "RANSOMWARE_LIVE", "VEILLE_LLM"])
def test_non_blf_and_mixed_incidents_unchanged(replay, source):
    item, fact, old, old_fact = replay
    rich = replace(item, Source_ID=source, Item_ID="ITM-rich")
    rich_fact = {**old_fact, "Item_ID": rich.Item_ID, "Source_ID": source}
    before = dict(rich_fact)
    blf.enrich([item, rich, old], [fact, rich_fact, old_fact])
    assert rich_fact == before
    assert not fact.get("Activity_Description")


@pytest.mark.parametrize("url,quote,organisation,accepted", [
    ("https://example.org/about", ACTIVITY, "PassPass", True),
    ("", ACTIVITY, "PassPass", False),
    ("https://example.org/about", "", "PassPass", False),
    ("https://example.org/about", ACTIVITY, "Other", False),
])
def test_external_contract(replay, url, quote, organisation, accepted):
    item, fact, _, _ = replay
    class Provider:
        def resolve(self, name):
            return blf.ActivityEvidence(organisation, ACTIVITY, quote, url, .9, "official-test")
    blf.enrich([item], [fact], provider=Provider())
    assert bool(fact.get("Activity_Description")) == accepted


def test_registered_alias_with_distinct_spelling(replay, monkeypatch):
    item, fact, old, old_fact = replay
    item.Organisation_Raw = "Mobilité Exemple"
    item.Organisation_Key = "mobilite exemple"
    monkeypatch.setattr(org_identity, "ORGANISATION_IDENTITY_REGISTRY", {"mobilite exemple": "passpass"})
    blf.enrich([item, old], [fact, old_fact])
    assert sector_resolution.resolve_item(item, fact, {}).sector == "Transport / Logistique"


def test_replay_keeps_semantic_mapping_only_for_unchanged_evidence(replay):
    item, fact, old, old_fact = replay
    blf.enrich([item, old], [fact, old_fact])
    fact["Activity_Sector_Semantic"] = "Transport / Logistique"
    blf.enrich([item, old], [fact, old_fact])
    assert fact["Activity_Sector_Semantic"] == "Transport / Logistique"
    blf.enrich([item], [fact])
    assert not fact["Activity_Sector_Semantic"]
