from types import SimpleNamespace

from cyberwatch import cli, status


def test_live_repeat_compares_two_isolated_runs(monkeypatch):
    reports = [
        SimpleNamespace(
            overall=status.OK,
            items_hash="items",
            incidents_hash="incidents",
            items=[1, 2], incidents=[1],
            outcomes=[SimpleNamespace(source_id="A", status=status.OK, units_done=1, units_expected=1, items_seen=3, items_in_window=2, items_collected=2)],
        ),
        SimpleNamespace(
            overall=status.OK,
            items_hash="items",
            incidents_hash="incidents",
            items=[1, 2], incidents=[1],
            outcomes=[SimpleNamespace(source_id="A", status=status.OK, units_done=1, units_expected=1, items_seen=3, items_in_window=2, items_collected=2)],
        ),
    ]
    monkeypatch.setattr(cli, "execute", lambda *args, **kwargs: reports.pop(0))
    args = SimpleNamespace(as_of="2026-08-14T00:00:00+04:00", start=None, layers="all")
    assert cli.cmd_test_live_repeat(args) == 0
