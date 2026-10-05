"""Regressions observed in the September 2026 collection corpus, offline."""
import json
from dataclasses import replace

import pytest

from cyberwatch import config, dedup_ai, dedup_review, enrichment, normalize, org_identity, production, sector, store
from cyberwatch.collectors.base import RawEntry
from cyberwatch.collectors.cyberattaque_org import (
    organisation_from_cyberattaque_entry, repair_existing_identities,
)
from cyberwatch.duplicate_audit import find_daily_llm_candidates


@pytest.mark.parametrize("name", [
    "Fédération flamande de judo", "Fédération francophone de Gymnastique",
    "Fédération Royale Belge de Tennis de Table", "Fédération Royale Belge des Échecs",
    "Fédération Française de Spéléologie",
])
def test_foreign_and_french_sports_federations_have_a_business_sector(name):
    assert sector.classify_sector_name(name) == config.SECTOR_SPORT
    assert sector.classify_sector_name("Fédération belge du commerce") != config.SECTOR_SPORT


@pytest.mark.parametrize("activity,expected", [
    ("Century 21 est l’un des principaux réseaux immobiliers français, constitué de "
     "centaines d’agences franchisées réparties sur le territoire.", config.SECTOR_CONSTRUCTION),
    ("Réassurez-moi est un courtier en assurances accompagnant les particuliers dans "
     "la comparaison et la souscription d’assurances emprunteur et de mutuelles santé.",
     config.SECTOR_FINANCE),
    ("Acme fournit des réseaux informatiques aux entreprises.", config.SECTOR_TECH),
])
def test_principal_activity_outweighs_network_or_health_product_words(activity, expected):
    assert sector.classify_sector_activity(activity) == expected


@pytest.mark.parametrize("title,name", [
    ("Propertips by iad visé par une cyberattaque : 413 000 clients en fuite", "Propertips by iad"),
    ("Revolut piégé par de fausses demandes gouvernementales", "Revolut"),
])
def test_editorial_tail_is_removed_from_victim_identity(title, name):
    assert organisation_from_cyberattaque_entry(RawEntry(title=title), {}) == name


def test_daily_historical_repair_preserves_native_identity_and_unresolved_rows(make_item):
    victim = make_item(source="CYBERATTAQUE_ORG", org="Groupe MGEL visé par une cyberattaque",
                       title="Groupe MGEL visé par une cyberattaque : des données exposées")
    victim.Source_Item_ID = "3152"
    from cyberwatch.identity import item_id
    victim.Item_ID = item_id(victim.Source_ID, victim.Published_Date, victim.Organisation_Key,
                             victim.URL, victim.Source_Item_ID)
    previous_id = victim.Item_ID
    unresolved = make_item(source="CYBERATTAQUE_ORG", org="Victime identifiée dans le corps",
                           title="Une attaque informatique confirmée")
    unresolved.Source_Item_ID = "3153"
    repaired, count = repair_existing_identities([victim, unresolved], editorial_tails_only=True)
    assert count == 1
    assert len(repaired) == 2
    assert victim.Organisation_Raw == "Groupe MGEL"
    assert victim.Item_ID == previous_id
    assert unresolved.Organisation_Raw == "Victime identifiée dans le corps"


def test_foreign_federation_cannot_inherit_french_feed_location(make_item):
    foreign = make_item(source="FRENCHBREACHES", org="Fédération Royale Belge des Échecs",
                        location=config.LOC_FRANCE)
    french = make_item(source="FRENCHBREACHES", org="Fédération française de basketball",
                       location=config.LOC_FRANCE)
    enrichment.backfill_unknowns([foreign, french], {})
    assert foreign.Location == config.LOC_INCONNU
    assert french.Location == config.LOC_FRANCE
    enrichment.backfill_unknowns([foreign], {})
    assert foreign.Location == config.LOC_INCONNU


def test_published_partial_source_is_visible_even_when_overall_run_is_ok(monkeypatch):
    monkeypatch.setattr(store, "load_run_sources", lambda: [
        {"Run_ID": "OLD", "Source_ID": "FRENCHBREACHES", "Status": "FAIL"},
        {"Run_ID": "CURRENT", "Source_ID": "VEILLE_LLM", "Status": "PARTIAL",
         "Coverage": "100", "Reason_Code": "INCOMPLETE", "Comment": "freshness_days=7"},
    ])
    monkeypatch.setattr(store, "load_snapshot", lambda: {"Run_ID": "CURRENT"})
    payload = production.health_payload()
    assert len(payload["source_coverage"]) == 1
    assert any("VEILLE_LLM : PARTIAL (INCOMPLETE)" in r for r in payload["alert_reasons"])
    assert production.published_source_coverage({}) == []


def test_strong_pending_identity_precedes_older_fuzzy_queue(make_item, tmp_path, monkeypatch):
    monkeypatch.setattr(normalize, "ORGANISATION_ALIASES", {})
    monkeypatch.setattr(org_identity, "ORGANISATION_IDENTITY_REGISTRY", {})
    strong_left = make_item(source="A", org="Scorenco", published="2026-09-27")
    strong_right = make_item(source="B", org="Score’n’co", published="2026-09-27")
    strong = find_daily_llm_candidates([strong_left], [strong_right])[0]
    weak = replace(strong, signals=replace(strong.signals, compact_match=False,
                   fuzzy_score=0.6, organisation_similarity=0.6))
    weak = replace(weak, left=replace(strong_left, Item_ID="WEAK-LEFT"),
                   right=replace(strong_right, Item_ID="WEAK-RIGHT"))
    state = dedup_ai.DedupAiRunState(True, "test", "gpt-5-mini", tmp_path / "cache.csv")
    state.run_id = "NEW"
    state.pending_rows = [{"pair_key": dedup_ai.candidate_id(weak), "first_seen": "OLD"}]
    entries = dedup_ai._uncached_batch_entries([weak, strong], {}, state, {}, {})
    assert entries[0][0] == strong
    rows = [{"pair_key": dedup_ai.candidate_id(c), "left": c.left.Item_ID,
             "right": c.right.Item_ID, "first_seen": age, "status": "NOT_REVIEWED_CAPACITY"}
            for c, age in [(weak, "OLD"), (strong, "NEW")]]
    # Use genuine weak name similarity when regenerating retry signals.
    weak.left.Organisation_Raw = "Colec"
    weak.left.Organisation_Key = "colec"
    weak.right.Organisation_Raw = "ColiSport"
    weak.right.Organisation_Key = "colisport"
    retried = dedup_review.retry_candidates(rows, [strong_left, strong_right, weak.left, weak.right], limit=1)
    assert dedup_ai.candidate_id(retried[0]) == dedup_ai.candidate_id(strong)


def test_batch_budget_counts_exact_wire_json_and_fills_remaining_space(make_item, tmp_path, monkeypatch):
    monkeypatch.setattr(normalize, "ORGANISATION_ALIASES", {})
    monkeypatch.setattr(org_identity, "ORGANISATION_IDENTITY_REGISTRY", {})
    left = make_item(source="A", org="Scorenco")
    right = make_item(source="B", org="Score’n’co")
    candidate = find_daily_llm_candidates([left], [right])[0]
    state = dedup_ai.DedupAiRunState(True, "test", "gpt-5-mini", tmp_path / "cache.csv")
    first = (candidate, {"evidence": "é" * 80}, "a")
    second = (replace(candidate, left=replace(left, Item_ID="B")), {"evidence": "b" * 60}, "b")
    third = (replace(candidate, left=replace(left, Item_ID="C")), {"evidence": "c"}, "c")
    state.max_context_chars = len(dedup_ai._batch_body([first, third], state))
    selected = dedup_ai._select_batch_entries([first, second, third], state, {})
    assert selected == [first, third]
    body = dedup_ai._batch_body(selected, state)
    assert len(body) == state.max_context_chars
    assert json.loads(body[len(dedup_ai.BATCH_PREAMBLE):])["candidates"] == [first[1], third[1]]
