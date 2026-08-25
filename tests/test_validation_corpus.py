from __future__ import annotations

import json

from cyberwatch import config, runner
from cyberwatch.collectors.base import CollectResult, RawEntry, SourceSpec
from cyberwatch.dedup import build_incidents
from cyberwatch.validation_corpus import ValidationCorpus, canonical_url


def _manifest(tmp_path):
    path = tmp_path / "corpus.json"
    path.write_text(json.dumps({
        "name": "test-corpus",
        "targets": [
            {"case": "one", "source_id": "FRENCHBREACHES", "published_date": "2026-08-20", "url": "https://example.test/a"},
            {"case": "one", "source_id": "CYBERATTAQUE_ORG", "published_date": "2026-08-20", "url": "https://example.test/b/"},
        ],
    }), encoding="utf-8")
    return ValidationCorpus.load(path)


def test_validation_corpus_accepts_only_the_exact_source_url(tmp_path):
    corpus = _manifest(tmp_path)

    assert corpus.accepts("FRENCHBREACHES", "https://example.test/a#fragment")
    assert corpus.accepts("CYBERATTAQUE_ORG", "https://example.test/b")
    assert not corpus.accepts("FRENCHBREACHES", "https://example.test/b")
    assert canonical_url("HTTPS://EXAMPLE.TEST/a/#x") == "https://example.test/a"


def test_validation_corpus_audit_requires_one_complete_incident(tmp_path, make_item):
    corpus = _manifest(tmp_path)
    first = make_item(source="FRENCHBREACHES", org="Exemple SA", published="2026-08-20", url="https://example.test/a")
    second = make_item(source="CYBERATTAQUE_ORG", org="Exemple SA", published="2026-08-20", url="https://example.test/b")
    incidents = build_incidents([first, second])

    assert corpus.audit([first, second], incidents) == []
    assert "cible source manquante" in corpus.audit([first], build_incidents([first]))[0]


def test_run_source_discards_non_whitelisted_entries_before_fact_extraction(tmp_path, monkeypatch, make_item):
    corpus = _manifest(tmp_path)
    spec = SourceSpec(
        source_id="FRENCHBREACHES", layer=config.LAYER_CORE, zone=config.LOC_FRANCE,
        default_threat=config.THREAT_LEAK, params={"title_is_organisation": True},
    )
    result = CollectResult(entries=[
        RawEntry(title="Exemple SA", url="https://example.test/a", published="2026-08-20"),
        RawEntry(title="Hors corpus", url="https://example.test/no", published="2026-08-20"),
    ], reached_boundary=True)
    monkeypatch.setattr(runner, "get_collector", lambda _name: type("Collector", (), {"collect": lambda *_: result})())
    monkeypatch.setattr(
        runner, "entry_to_item",
        lambda entry, *_args: make_item(source="FRENCHBREACHES", org=entry.title, published=entry.published, url=entry.url),
    )
    extracted = []
    monkeypatch.setattr(runner, "_extract_source_fact_for_entry", lambda item, *_: extracted.append(item.URL) or {"Item_ID": item.Item_ID})
    context = runner.make_run_context(
        runner.MODE_CREATE, "2026-08-24T10:00:00+04:00", "2026-08-01", [config.LAYER_CORE],
        validation_corpus_path=str(tmp_path / "corpus.json"),
    )

    _outcome, items, facts = runner.run_source(
        object(), spec, context, {}, {}, {}, {}, None, {}, [],
    )

    assert [item.URL for item in items] == ["https://example.test/a"]
    assert extracted == ["https://example.test/a"]
    assert len(facts) == 0


def test_validation_corpus_adds_the_allowlist_to_the_collector_spec(tmp_path):
    corpus = _manifest(tmp_path)
    spec = SourceSpec(source_id="FRENCHBREACHES", layer=config.LAYER_CORE, zone=config.LOC_FRANCE)
    constrained = runner.replace(
        spec, params={**spec.params, "validation_allowed_urls": corpus.urls_for_source(spec.source_id)}
    )

    from cyberwatch.collectors.base import entry_allowed_before_enrichment
    assert entry_allowed_before_enrichment(constrained, RawEntry(url="https://example.test/a"))
    assert not entry_allowed_before_enrichment(constrained, RawEntry(url="https://example.test/no"))


def test_editorial_collectors_do_not_enrich_entries_outside_the_allowlist(monkeypatch):
    from cyberwatch.collectors import cyberattaque_rich, editorial_rich

    entries = [RawEntry(url="https://example.test/keep"), RawEntry(url="https://example.test/drop")]
    result = CollectResult(entries=entries)
    spec = SourceSpec(
        source_id="CYBERATTAQUE_ORG", layer=config.LAYER_CORE, zone=config.LOC_FRANCE,
        params={"validation_allowed_urls": ["https://example.test/keep"]},
    )
    monkeypatch.setattr(cyberattaque_rich.CyberattaqueOrgCollector, "collect", lambda *_: result)
    cyber_calls = []
    monkeypatch.setattr(cyberattaque_rich, "enrich_entry_metadata", lambda entry: cyber_calls.append(entry.url))
    cyberattaque_rich.CyberattaqueRichCollector().collect(object(), spec, object())

    monkeypatch.setattr(editorial_rich.FeedCollector, "collect", lambda *_: result)
    editorial_calls = []
    monkeypatch.setattr(
        editorial_rich,
        "apply_rich_extractor",
        lambda entry, *_args, **_kwargs: editorial_calls.append(entry.url),
    )
    editorial_rich.EditorialRichFeedCollector().collect(object(), spec, object())

    assert cyber_calls == ["https://example.test/keep"]
    assert editorial_calls == ["https://example.test/keep"]


def test_validation_corpus_flag_exists_on_create_and_maj():
    """`--validation-corpus` n'avait longtemps existé que sur `create` alors
    que `runner.make_run_context` le prend en charge indifféremment des deux
    modes — un oubli de câblage CLI, pas une restriction voulue."""
    from cyberwatch.cli import build_parser

    parser = build_parser()
    for subcommand in ("create", "maj"):
        args = parser.parse_args([subcommand, "--validation-corpus", "corpus.json"])
        assert args.validation_corpus == "corpus.json"
