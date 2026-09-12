from cyberwatch import config, identity, runner, sources, status
from cyberwatch.collectors.base import SourceSpec
from cyberwatch.model import Item


def _item(source_id: str, date: str, url: str) -> Item:
    key = source_id.lower()
    return Item(
        Item_ID=identity.item_id(source_id, date, key, url),
        Source_ID=source_id,
        Published_Date=date,
        Event_Date=date,
        Organisation_Raw=source_id,
        Organisation_Key=key,
        Threat="Intrusion",
        Location=config.LOC_REUNION,
        URL=url,
    )


def test_replace_snapshot_keeps_full_source_snapshot_outside_daily_window(monkeypatch):
    replacement = SourceSpec(
        source_id="VEILLE_LLM",
        layer=config.LAYER_REGIONAL_WATCH,
        zone="La Réunion / Mayotte",
        params={"replace_snapshot": True},
    )
    regular = SourceSpec(
        source_id="REGULAR_TEST",
        layer=config.LAYER_REGIONAL_WATCH,
        zone="Test",
    )
    historical_replacement = _item(
        "VEILLE_LLM", "2026-02-19", "https://example.test/veille-historical"
    )
    historical_regular = _item(
        "REGULAR_TEST", "2026-02-19", "https://example.test/regular-historical"
    )
    current_regular = _item(
        "REGULAR_TEST", "2026-09-12", "https://example.test/regular-current"
    )

    context = runner.RunContext(
        run_id="RUN-TEST-REPLACEMENT-SNAPSHOT",
        as_of="2026-09-12T10:00:00+04:00",
        target_start="2026-09-11",
        target_end="2026-09-12",
        mode=runner.MODE_MAJ,
        layers=[config.LAYER_REGIONAL_WATCH],
    )
    report = runner.RunReport(context=context)

    monkeypatch.setattr(sources, "active_sources", lambda _layers: [replacement, regular])
    monkeypatch.setattr(runner.watchlists, "known_organisations", lambda: {})
    monkeypatch.setattr(runner.watchlists, "entity_index", lambda: {})
    monkeypatch.setattr(runner.watchlists, "entity_territories", lambda: {})
    monkeypatch.setattr(runner.enrichment, "load_reference", lambda: {})
    monkeypatch.setattr(runner.source_facts_retry, "load", lambda: [])
    monkeypatch.setattr(runner.store, "load_source_facts", lambda: [])
    monkeypatch.setattr(
        runner.runner_source_facts,
        "retry_pending",
        lambda _queued: ([], {}),
    )

    def fake_run_source(_client, spec, *_args, **_kwargs):
        items = (
            [historical_replacement]
            if spec.source_id == "VEILLE_LLM"
            else [historical_regular, current_regular]
        )
        return status.SourceOutcome(spec.source_id, spec.layer), items, []

    monkeypatch.setattr(runner, "run_source", fake_run_source)

    collected, _ = runner._collect_for_run(report, context, [], set())

    assert historical_replacement in collected
    assert current_regular in collected
    assert historical_regular not in collected
    assert historical_replacement in report.items
    assert {outcome.source_id: outcome.items_collected for outcome in report.outcomes} == {
        "VEILLE_LLM": 1,
        "REGULAR_TEST": 1,
    }
