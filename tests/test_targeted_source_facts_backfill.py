from __future__ import annotations

import json

from cyberwatch import source_facts as sf
from cyberwatch.collectors.base import SourceSpec
from cyberwatch.http import Budget, FetchResult
from cyberwatch.model import Item
from scripts import backfill_source_fact_summaries as backfill


def _item(
    item_id: str,
    source_id: str = "CYBERATTAQUE_ORG",
    published: str = "2026-08-01",
    source_item_id: str = "",
    url: str = "",
) -> Item:
    return Item(
        Item_ID=item_id,
        Source_ID=source_id,
        Source_Item_ID=source_item_id,
        Published_Date=published,
        Organisation_Raw="Exemple SA",
        Organisation_Key="exemple sa",
        Title="Exemple SA : cyberattaque",
        URL=url,
    )


class FakeClient:
    def __init__(self, responses: dict[str, FetchResult]):
        self.responses = responses
        self.urls: list[str] = []
        self.run_budget = Budget(100, 100)

    def source_budget(self):
        return Budget(20, 100)

    def fetch(self, url, _budget=None):
        self.urls.append(url)
        return self.responses.get(
            url,
            FetchResult(False, url, status_code=404, reason_code="HTTP_404"),
        )


def test_select_candidates_only_missing_summaries_and_is_deterministic():
    items = [
        _item("old", published="2026-07-01"),
        _item("new", published="2026-08-02"),
        _item("ok", published="2026-08-03"),
        _item("other", source_id="BONJOURLAFUITE", published="2026-08-04"),
        _item("fb", source_id="FRENCHBREACHES", published="2026-08-01"),
    ]
    facts = [
        {"Item_ID": "ok", "Source_ID": "CYBERATTAQUE_ORG", "Summary": "Présente"},
        {"Item_ID": "old", "Source_ID": "CYBERATTAQUE_ORG", "Summary": ""},
        {"Item_ID": "fb", "Source_ID": "FRENCHBREACHES", "Summary": ""},
    ]

    selected, metrics = backfill.select_candidates(items, facts, max_items=2)

    assert [item.Item_ID for item in selected] == ["new", "fb"]
    assert metrics["candidates_total"] == 3
    assert metrics["candidates_without_source_fact"] == 1
    assert metrics["selected_by_source"] == {
        "CYBERATTAQUE_ORG": 1,
        "FRENCHBREACHES": 1,
    }


def test_select_candidates_respects_explicit_item_ids():
    items = [_item("a"), _item("b", source_id="FRENCHBREACHES")]
    selected, metrics = backfill.select_candidates(
        items,
        [],
        item_ids={"b", "missing"},
        max_items=10,
    )
    assert [item.Item_ID for item in selected] == ["b"]
    assert metrics["requested_not_eligible"] == ["missing"]


def test_explicit_item_id_requalifies_an_existing_summary():
    items = [_item("a")]
    selected, _ = backfill.select_candidates(
        items,
        [{"Item_ID": "a", "Source_ID": "CYBERATTAQUE_ORG", "Summary": "Ancienne synthèse"}],
        item_ids={"a"},
    )
    assert [item.Item_ID for item in selected] == ["a"]


def test_include_existing_requalifies_les_plus_recents():
    items = [_item("old", published="2026-08-01"), _item("new", published="2026-08-02")]
    facts = [{"Item_ID": item.Item_ID, "Source_ID": item.Source_ID, "Summary": "Présente"} for item in items]
    selected, metrics = backfill.select_candidates(items, facts, include_existing=True, max_items=1)
    assert [item.Item_ID for item in selected] == ["new"]
    assert metrics["include_existing"] is True


def test_hydrate_cyberattaque_uses_native_wordpress_id():
    item = _item(
        "wp",
        source_item_id="123",
        url="https://www.cyberattaque.org/exemple-sa-cyberattaque/",
    )
    spec = SourceSpec(
        source_id="CYBERATTAQUE_ORG",
        layer="core",
        zone="France",
        start_url="https://www.cyberattaque.org/type/attaque/",
        params={"include_content": True},
    )
    url = (
        "https://www.cyberattaque.org/wp-json/wp/v2/posts/123?"
        "_fields=id%2Cdate%2Clink%2Ctitle%2Cexcerpt%2Ccontent%2Ccategories"
    )
    payload = {
        "id": 123,
        "date": "2026-08-01T10:00:00",
        "link": item.URL,
        "title": {"rendered": "Exemple SA : cyberattaque"},
        "excerpt": {"rendered": "<p>Extrait</p>"},
        "content": {"rendered": "<p>Une intrusion a été confirmée.</p>"},
        "categories": [1],
    }
    client = FakeClient({
        url: FetchResult(True, url, 200, json.dumps(payload)),
    })

    entry = backfill.hydrate_cyberattaque_entry(client, item, spec)

    assert entry is not None
    assert entry.content == "Une intrusion a été confirmée."
    assert entry.organisation == "Exemple SA"
    assert entry.source_item_id == "123"
    assert client.urls == [url]


def test_hydrate_cyberattaque_falls_back_to_url_slug():
    item = _item(
        "wp-slug",
        url="https://www.cyberattaque.org/exemple-sa-cyberattaque/",
    )
    spec = SourceSpec(
        source_id="CYBERATTAQUE_ORG",
        layer="core",
        zone="France",
        start_url="https://www.cyberattaque.org/type/attaque/",
        params={"include_content": True},
    )
    url = (
        "https://www.cyberattaque.org/wp-json/wp/v2/posts?"
        "slug=exemple-sa-cyberattaque&_fields="
        "id%2Cdate%2Clink%2Ctitle%2Cexcerpt%2Ccontent%2Ccategories"
    )
    payload = [{
        "id": 456,
        "date": "2026-08-01T10:00:00",
        "link": item.URL,
        "title": {"rendered": "Exemple SA : cyberattaque"},
        "excerpt": {"rendered": ""},
        "content": {"rendered": "<p>Contenu détaillé.</p>"},
        "categories": [1],
    }]
    client = FakeClient({
        url: FetchResult(True, url, 200, json.dumps(payload)),
    })

    entry = backfill.hydrate_cyberattaque_entry(client, item, spec)

    assert entry is not None
    assert entry.content == "Contenu détaillé."
    assert entry.organisation == "Exemple SA"


def test_hydrate_frenchbreaches_uses_stable_detail_text():
    item = _item(
        "fb",
        source_id="FRENCHBREACHES",
        url="https://frenchbreaches.com/alerte/exemple",
    )
    spec = SourceSpec(
        source_id="FRENCHBREACHES",
        layer="core",
        zone="France",
        start_url="https://frenchbreaches.com/feed.xml",
    )
    html = (
        "<article>Intrusion confirmée sur un serveur externe.</article>"
        "<script>texte dynamique à ignorer</script>"
        "<div>Alertes liées</div><div>Autre incident</div>"
    )
    client = FakeClient({
        item.URL: FetchResult(True, item.URL, 200, html),
    })

    entry = backfill.hydrate_frenchbreaches_entry(client, item, spec)

    assert entry is not None
    assert entry.content == "Intrusion confirmée sur un serveur externe."
    assert "dynamique" not in entry.content
    assert entry.organisation == "Exemple SA"


def test_run_backfill_dry_run_has_no_network_or_writes(monkeypatch):
    item = _item("dry")
    monkeypatch.setattr(backfill.store, "load_items", lambda: [item])
    monkeypatch.setattr(backfill.store, "load_source_facts", lambda: [])
    monkeypatch.setattr(
        backfill,
        "hydrate_entry",
        lambda *_args: (_ for _ in ()).throw(AssertionError("network")),
    )
    monkeypatch.setattr(
        backfill.store,
        "save_source_facts",
        lambda *_args: (_ for _ in ()).throw(AssertionError("write")),
    )

    metrics = backfill.run_backfill(dry_run=True)

    assert metrics["selected"] == 1
    assert metrics["dry_run"] is True


def test_run_backfill_merges_only_source_facts_and_builds(monkeypatch):
    item = _item("run")
    old = {
        "Item_ID": "run",
        "Source_ID": "CYBERATTAQUE_ORG",
        "Summary": "",
        "Impact": "Impact historique",
        "Evidence_JSON": sf._dumps_json({"Impact": "preuve impact"}),
    }
    new = {
        "Item_ID": "run",
        "Source_ID": "CYBERATTAQUE_ORG",
        "Summary": "Synthèse récupérée.",
        "Impact": "",
        "Evidence_JSON": sf._dumps_json({"Summary": "preuve synthèse"}),
    }
    saved: list[list[dict]] = []
    built: list[bool] = []
    flushed: list[bool] = []

    monkeypatch.setattr(backfill.store, "load_items", lambda: [item])
    monkeypatch.setattr(backfill.store, "load_source_facts", lambda: [old])
    monkeypatch.setattr(backfill, "source_specs", lambda: {
        "CYBERATTAQUE_ORG": SourceSpec(
            source_id="CYBERATTAQUE_ORG", layer="core", zone="France"
        )
    })
    monkeypatch.setattr(
        backfill,
        "hydrate_entry",
        lambda *_args: backfill.RawEntry(
            title=item.Title,
            content="Une intrusion est confirmée.",
            organisation=item.Organisation_Raw,
        ),
    )
    monkeypatch.setattr(backfill.source_facts, "extract_source_fact", lambda *_args: new)
    monkeypatch.setattr(backfill.store, "save_source_facts", lambda rows: saved.append(rows))
    monkeypatch.setattr(backfill.source_facts_ai, "runtime_stats", lambda: {"calls_attempted": 1})
    monkeypatch.setattr(backfill.source_facts_ai, "_flush_runtime", lambda: flushed.append(True))
    monkeypatch.setattr(backfill.site, "build", lambda: built.append(True))

    client = FakeClient({})
    metrics = backfill.run_backfill(client=client)

    assert metrics["headlines_accepted"] == 1
    assert metrics["incidents_published_without_headline"] == 0
    assert len(saved) == 1
    assert saved[0][0]["Summary"] == "Synthèse récupérée."
    assert saved[0][0]["Impact"] == "Impact historique"
    evidence = json.loads(saved[0][0]["Evidence_JSON"])
    assert evidence["Impact"] == "preuve impact"
    assert evidence["Summary"] == "preuve synthèse"
    assert flushed == [True]
    assert built == [True]


def test_latest_incidents_selects_one_source_per_deduplicated_incident():
    same_incident = [
        _item("co", published="2026-08-03", source_item_id="1"),
        _item("fb", source_id="FRENCHBREACHES", published="2026-08-04", source_item_id="2"),
    ]
    other = _item("other", published="2026-08-02", source_item_id="3")
    selected, metrics = backfill.select_latest_incident_candidates(same_incident + [other], max_items=2)
    assert len(selected) == 2
    assert selected[0].Item_ID == "co"
    assert metrics["one_source_per_incident"] is True


def test_backfill_keeps_valid_editorial_headline_returned_by_ai(monkeypatch):
    """An adapter's old technical summary must not overwrite the AI return."""
    item = _item("headline")
    saved = []
    monkeypatch.setattr(backfill.store, "load_items", lambda: [item])
    monkeypatch.setattr(backfill.store, "load_source_facts", lambda: [])
    monkeypatch.setattr(backfill, "source_specs", lambda: {
        "CYBERATTAQUE_ORG": SourceSpec(source_id="CYBERATTAQUE_ORG", layer="core", zone="France")
    })
    monkeypatch.setattr(backfill, "hydrate_entry", lambda *_: backfill.RawEntry(
        title=item.Title, content="Une intrusion est confirmée.", organisation=item.Organisation_Raw,
    ))
    monkeypatch.setattr(backfill.source_facts, "extract_source_fact", lambda *_: {
        "Item_ID": item.Item_ID, "Source_ID": item.Source_ID,
        "Summary": "Éléments documentés : 43 Go de données.",
    })
    monkeypatch.setattr(backfill.source_facts_ai, "enrich", lambda *_: {
        "summary": "Exemple SA a confirmé une intrusion informatique affectant ses services."
    })
    monkeypatch.setattr(backfill.source_facts_ai, "runtime_stats", lambda: {"calls_attempted": 0})
    monkeypatch.setattr(backfill.source_facts_ai, "_flush_runtime", lambda: None)
    monkeypatch.setattr(backfill.store, "save_source_facts", lambda rows: saved.append(rows))
    monkeypatch.setattr(backfill.site, "build", lambda: None)

    metrics = backfill.run_backfill(replay_summary_cache=True)

    assert metrics["headlines_accepted"] == 1
    assert saved[0][0]["Summary"].startswith("Exemple SA a confirmé")
