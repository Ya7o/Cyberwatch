from cyberwatch import config, runner, status
from cyberwatch.collectors.base import CollectResult, RawEntry, SourceSpec, Window
from cyberwatch.collectors.kwezi import KweziCollector
from cyberwatch.collectors.wordpress import WordPressCollector


SPEC = SourceSpec("KWEZI_NUMERIQUE", config.LAYER_LOCAL_MEDIA, config.LOC_MAYOTTE)


def test_kwezi_preserves_metrics_before_window_filter(monkeypatch):
    base = CollectResult(
        entries=[RawEntry(title="Victime", published="2026-08-10")],
        items_seen=150, items_in_window=12, units_done=3, units_expected=3,
    )
    monkeypatch.setattr(WordPressCollector, "collect", lambda *args: base)
    result = KweziCollector().collect(None, SPEC, Window("2026-08-01", "2026-08-31"))
    assert result.items_seen == 150
    assert result.items_in_window == 12
    assert len(result.entries) == 1
    assert result.resolve()[0] == status.OK


def test_kwezi_zero_in_window_is_verified_ok(monkeypatch):
    base = CollectResult(items_seen=150, items_in_window=0, units_done=3, units_expected=3)
    monkeypatch.setattr(WordPressCollector, "collect", lambda *args: base)
    result = KweziCollector().collect(None, SPEC, Window("2026-08-01", "2026-08-31"))
    assert result.items_seen == 150
    assert result.items_in_window == 0
    assert result.resolve()[0] == status.OK


def test_kwezi_diagnostic_distingue_cyber_victimes_et_items(monkeypatch):
    class Collector:
        def collect(self, client, spec, window):
            return CollectResult(
                entries=[
                    RawEntry(
                        title="Services perturbés", published="2026-08-10",
                        content="La mairie de Mamoudzou a été victime d'une cyberattaque.",
                        url="https://example.test/mairie", source_item_id="1",
                    ),
                    RawEntry(
                        title="Alerte cyber", published="2026-08-10",
                        content="Une cyberattaque a touché plusieurs services.",
                        url="https://example.test/sans-victime", source_item_id="2",
                    ),
                ],
                items_seen=12, items_in_window=2, units_done=1, units_expected=1,
                status_override=status.OK,
            )

    spec = SourceSpec(
        "KWEZI_NUMERIQUE", config.LAYER_LOCAL_MEDIA, config.LOC_MAYOTTE,
        collector="fake",
    )
    monkeypatch.setattr(runner, "get_collector", lambda name: Collector())
    context = runner.make_run_context(
        runner.MODE_CREATE, as_of="2026-08-14T00:00:00+04:00",
        layers=[config.LAYER_LOCAL_MEDIA],
    )

    outcome, items, _ = runner.run_source(None, spec, context, {}, {})

    assert len(items) == 1
    assert outcome.items_collected == 1
    assert "articles_cyber=2" in outcome.comment
    assert "victims_identified=1" in outcome.comment
