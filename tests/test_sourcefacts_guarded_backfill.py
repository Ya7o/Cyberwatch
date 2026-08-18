from __future__ import annotations

import json

from cyberwatch.model import Item
from scripts import run_sourcefacts_backfill_guarded as guarded


def _item(item_id: str) -> Item:
    return Item(
        Item_ID=item_id,
        Source_ID="CYBERATTAQUE_ORG",
        Organisation_Raw="Exemple SA",
        Published_Date="2026-08-18",
    )


def test_consumed_historical_retry_is_skipped_on_next_run(monkeypatch, tmp_path):
    items = [_item("ITM-1"), _item("ITM-2")]
    monkeypatch.setattr(
        guarded,
        "candidate_pool",
        lambda **_kwargs: (items, {"candidates_total": 2}),
    )
    calls: list[str] = []

    def fake_run_backfill(*, item_ids, **_kwargs):
        item_id = next(iter(item_ids))
        calls.append(item_id)
        return {
            "summary_recovered": 0,
            "abstained_retry_item_ids": [item_id],
            "abstained_retry_restored": 0,
        }

    monkeypatch.setattr(guarded.backfill, "run_backfill", fake_run_backfill)
    ledger = tmp_path / "ledger.json"

    first = guarded.run_guarded(
        max_items=2,
        max_seconds=60,
        ledger_path=ledger,
    )
    second = guarded.run_guarded(
        max_items=2,
        max_seconds=60,
        ledger_path=ledger,
    )

    assert first["historical_retry_consumed"] == 2
    assert second["selected"] == 0
    assert calls == ["ITM-1", "ITM-2"]
    assert json.loads(ledger.read_text(encoding="utf-8"))["item_ids"] == [
        "ITM-1",
        "ITM-2",
    ]


def test_technical_restore_does_not_consume_historical_retry(monkeypatch, tmp_path):
    item = _item("ITM-technical")
    monkeypatch.setattr(
        guarded,
        "candidate_pool",
        lambda **_kwargs: ([item], {"candidates_total": 1}),
    )

    def fake_run_backfill(**_kwargs):
        return {
            "summary_recovered": 0,
            "abstained_retry_item_ids": [item.Item_ID],
            "abstained_retry_restored": 1,
        }

    monkeypatch.setattr(guarded.backfill, "run_backfill", fake_run_backfill)
    ledger = tmp_path / "ledger.json"

    result = guarded.run_guarded(
        max_items=1,
        max_seconds=60,
        ledger_path=ledger,
    )

    assert result["historical_retry_consumed"] == 0
    assert result["historical_retry_technical_restore"] == 1
    assert guarded.load_ledger(ledger) == set()


def test_time_budget_stops_between_items(monkeypatch, tmp_path):
    items = [_item("ITM-1"), _item("ITM-2")]
    monkeypatch.setattr(
        guarded,
        "candidate_pool",
        lambda **_kwargs: (items, {"candidates_total": 2}),
    )
    calls: list[str] = []

    def fake_run_backfill(*, item_ids, **_kwargs):
        calls.append(next(iter(item_ids)))
        return {
            "summary_recovered": 1,
            "abstained_retry_item_ids": [],
            "abstained_retry_restored": 0,
        }

    monkeypatch.setattr(guarded.backfill, "run_backfill", fake_run_backfill)
    ticks = iter([0.0, 0.0, 5.0, 11.0, 11.0])
    monkeypatch.setattr(guarded.time, "monotonic", lambda: next(ticks))

    result = guarded.run_guarded(
        max_items=2,
        max_seconds=10,
        ledger_path=tmp_path / "ledger.json",
    )

    assert calls == ["ITM-1"]
    assert result["processed"] == 1
    assert result["stopped_by_time_budget"] is True
    assert result["remaining_selected"] == 1
