from cyberwatch import config, status
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
