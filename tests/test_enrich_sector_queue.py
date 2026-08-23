from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "enrich_sector_queue.py"
_SPEC = spec_from_file_location("enrich_sector_queue_script", SCRIPT)
_module = module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(_module)


def test_source_fact_victim_website_becomes_discovery_hint(monkeypatch):
    monkeypatch.setattr(
        _module.store,
        "load_items",
        lambda: [SimpleNamespace(Item_ID="ITM-1", Organisation_Key="bija industrie")],
    )
    monkeypatch.setattr(
        _module.store,
        "read_csv",
        lambda path: [
            {"Item_ID": "ITM-1", "Victim_Website": "bija-industrie.com"},
            {"Item_ID": "ITM-1", "Victim_Website": "https://bija-industrie.com"},
        ],
    )

    hints = _module._source_fact_website_hints()

    assert hints == {"bija industrie": ("https://bija-industrie.com",)}


def test_source_fact_hint_is_prioritised_but_never_replaces_other_hints():
    queue_row = {
        "Evidence_URLs": "https://cyberattaque.org/acme",
        "Evidence_Text": "preuve https://example.test/about",
    }
    cache_row = {"Evidence_URL": "https://registry.example/acme"}

    hints = _module._hint_urls(
        queue_row,
        cache_row,
        ("https://official.example/",),
    )

    assert hints[0] == "https://official.example/"
    assert "https://cyberattaque.org/acme" in hints
    assert "https://example.test/about" in hints
    assert "https://registry.example/acme" in hints


def test_unmatched_target_is_journalised_as_not_found_with_fetched_at():
    cache: dict[str, dict] = {}
    targets = [("acme sarl", "Acme Sarl", ())]

    marked = _module._mark_unmatched_targets_as_attempted(cache, targets, {}, "2026-08-23T10:00:00+04:00")

    assert marked == 1
    row = cache["acme sarl"]
    assert row["Match_Status"] == _module.org_enrichment.NOT_FOUND
    assert row["Fetched_At"] == "2026-08-23T10:00:00+04:00"
    assert row["Organisation_Key"] == "acme sarl"
    assert row["Query_Name"] == "Acme Sarl"


def test_matched_target_is_never_reclassified_as_not_found():
    cache: dict[str, dict] = {}
    targets = [("acme sarl", "Acme Sarl", ())]
    evidence_by_key = {"acme sarl": ("Acme Sarl", object())}

    marked = _module._mark_unmatched_targets_as_attempted(
        cache, targets, evidence_by_key, "2026-08-23T10:00:00+04:00"
    )

    assert marked == 0
    assert "acme sarl" not in cache


def test_unmatched_target_keeps_its_existing_match_status():
    cache = {"acme sarl": {"Match_Status": _module.org_enrichment.AMBIGUOUS, "Fetched_At": "2026-08-01T00:00:00+04:00"}}
    targets = [("acme sarl", "Acme Sarl", ())]

    _module._mark_unmatched_targets_as_attempted(cache, targets, {}, "2026-08-23T10:00:00+04:00")

    row = cache["acme sarl"]
    assert row["Match_Status"] == _module.org_enrichment.AMBIGUOUS
    assert row["Fetched_At"] == "2026-08-23T10:00:00+04:00"
