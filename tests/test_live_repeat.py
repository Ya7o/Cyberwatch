from types import SimpleNamespace

from cyberwatch import cli, config, status


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
    waits = []
    monkeypatch.setattr(cli.time, "sleep", waits.append)
    proof = {}
    monkeypatch.setattr(cli.store, "save_live_repeat", lambda payload: proof.update(payload))
    args = SimpleNamespace(as_of="2026-08-14T00:00:00+04:00", start=None, layers="all")
    assert cli.cmd_test_live_repeat(args) == 0
    assert proof["Result"] == "PASS"
    assert proof["Items_Hash_A"] == proof["Items_Hash_B"] == "items"
    assert waits == [config.RANSOMWARE_LIVE_RATE_LIMIT_SECONDS]


def test_live_repeat_failure_records_no_valid_proof(monkeypatch):
    reports = [
        SimpleNamespace(
            overall=status.OK, items_hash="items-a", incidents_hash="incidents",
            items=[1], incidents=[1],
            outcomes=[SimpleNamespace(source_id="A", status=status.OK, units_done=1, units_expected=1, items_seen=1, items_in_window=1, items_collected=1)],
        ),
        SimpleNamespace(
            overall=status.BROKEN, items_hash="items-b", incidents_hash="incidents",
            items=[1, 2], incidents=[1],
            outcomes=[SimpleNamespace(source_id="A", status=status.FAIL, units_done=0, units_expected=1, items_seen=0, items_in_window=0, items_collected=0)],
        ),
    ]
    monkeypatch.setattr(cli, "execute", lambda *args, **kwargs: reports.pop(0))
    monkeypatch.setattr(cli.time, "sleep", lambda _seconds: None)
    proof = {}
    monkeypatch.setattr(cli.store, "save_live_repeat", lambda payload: proof.update(payload))
    invalidated = []
    monkeypatch.setattr(cli.store, "invalidate_matching_live_repeat", lambda payload: invalidated.append(payload))
    args = SimpleNamespace(as_of="2026-08-14T00:00:00+04:00", start=None, layers="all")

    assert cli.cmd_test_live_repeat(args) == 1
    assert proof == {}
    assert invalidated and invalidated[0]["Result"] == "FAIL"
