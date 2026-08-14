"""Contrats du Lot 1 : médias mahorais, victime et couverture visible."""

from cyberwatch import config, enrichment, site, sources, status
from cyberwatch.collectors.base import RawEntry
from cyberwatch.dedup import build_incidents
from cyberwatch.runner import entry_to_item
from urllib.parse import urlparse


def _spec(source_id):
    return next(spec for spec in sources.ALL_SOURCES if spec.source_id == source_id)


def test_mayotte_direct_sources_are_declared_with_strict_victim_policy():
    for source_id in ("KWEZI_NUMERIQUE", "MAYOTTE_HEBDO_NUMERIQUE", "JOURNAL_DE_MAYOTTE"):
        spec = _spec(source_id)
        assert spec.active is True
        assert spec.location_rule == config.LOC_INCONNU
        assert spec.params.get("require_victim") is True
    assert _spec("JOURNAL_DE_MAYOTTE").params.get("publication_contract") is None


def test_mayotte_default_is_used_only_after_no_explicit_location():
    spec = _spec("MAYOTTE_HEBDO_NUMERIQUE")
    item = entry_to_item(
        RawEntry(title="Ville de Mamoudzou victime", organisation="Ville de Mamoudzou", content="cyberattaque", published="2026-06-11", url="https://x", source_item_id="1", location="France métropolitaine"),
        spec, "2026-08-14T00:00:00+04:00", {"ville de mamoudzou": "Ville de Mamoudzou"}, {}, {},
    )
    assert item is not None
    assert item.Location == config.LOC_FRANCE


def test_required_mayotte_source_absent_is_exposed_as_not_covered(monkeypatch):
    monkeypatch.setattr(site.store, "snapshot_state", lambda: (site.store.BASE_VALID, []))
    monkeypatch.setattr(site.store, "load_run_log", lambda: [{"Run_ID": "run"}])
    monkeypatch.setattr(site.store, "load_run_sources", lambda: [])
    monkeypatch.setattr(site.store, "load_entity_watch", lambda: [])
    payload = site.status_payload()
    assert any(row["id"] == "KWEZI_NUMERIQUE" and row["status"] == status.NOT_COVERED for row in payload["sources"])
    coverage = payload["coverage_groups"]["MAYOTTE_LOCAL"]
    assert coverage["expected"] == 3
    assert coverage["queried"] == 0
    assert coverage["coverage"] == "PARTIAL"


def test_mayotte_watcher_excludes_direct_publishers():
    direct = {
        urlparse(_spec(source_id).start_url).netloc.removeprefix("www.")
        for source_id in ("KWEZI_NUMERIQUE", "MAYOTTE_HEBDO_NUMERIQUE", "JOURNAL_DE_MAYOTTE")
    }
    watched = {domain.split("/", 1)[0].removeprefix("www.") for domain in sources.MAYOTTE_MEDIA}
    assert not direct & watched
    assert sources.MAYOTTE_MEDIA == []
    assert "la1ere.francetvinfo.fr/mayotte" in sources.MAYOTTE_CANDIDATE_MEDIA


def test_mamoudzou_multi_source_converges_through_explicit_aliases():
    known = {
        "ville de mamoudzou": "Ville de Mamoudzou",
        "mairie de mamoudzou": "Mairie de Mamoudzou",
        "commune de mamoudzou": "Commune de Mamoudzou",
    }
    items = []
    organisations = ("Ville de Mamoudzou", "Mairie de Mamoudzou", "Commune de Mamoudzou")
    for number, (source_id, organisation) in enumerate(zip(("KWEZI_NUMERIQUE", "MAYOTTE_HEBDO_NUMERIQUE", "JOURNAL_DE_MAYOTTE"), organisations), 1):
        items.append(entry_to_item(
            RawEntry(title=f"{organisation} victime d'une cyberattaque", organisation=organisation, content="messagerie affectée", published="2026-06-11", url=f"https://example.test/{number}", source_item_id=str(number)),
            _spec(source_id), "2026-08-14T00:00:00+04:00", known, {}, {}, enrichment.load_reference(),
        ))
    assert all(items)
    incident = build_incidents(items)
    assert len(incident) == 1
    assert incident[0].Organisation == "Mairie de Mamoudzou"
    assert incident[0].Localisation == config.LOC_MAYOTTE
    assert incident[0].Items_Count == 3
    assert incident[0].Sources.split(" | ") == ["JOURNAL_DE_MAYOTTE", "KWEZI_NUMERIQUE", "MAYOTTE_HEBDO_NUMERIQUE"]


def test_mayotte_direct_partial_blocks_snapshot():
    from cyberwatch.runner import outcome_blocks_snapshot

    partial = status.SourceOutcome("JOURNAL_DE_MAYOTTE", config.LAYER_LOCAL_MEDIA, status.PARTIAL, 60)
    core_partial = status.SourceOutcome("FRENCHBREACHES", config.LAYER_CORE, status.PARTIAL, 60)
    assert outcome_blocks_snapshot(partial, _spec("JOURNAL_DE_MAYOTTE"))
    assert outcome_blocks_snapshot(core_partial, _spec("FRENCHBREACHES"))
