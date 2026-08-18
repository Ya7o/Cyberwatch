#!/usr/bin/env python3
"""Orchestrateur borné et reprenable du backfill historique SourceFacts.

Le backfill métier existant reste l'autorité. Cette couche ajoute uniquement les
garde-fous opérationnels nécessaires à GitHub Actions : petits lots, budget temps,
progression visible et mémorisation persistante des retries historiques réellement
consommés.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from cyberwatch import store
from scripts import backfill_source_fact_summaries as backfill

DEFAULT_MAX_ITEMS = 10
DEFAULT_MAX_SECONDS = 480
DEFAULT_LEDGER_PATH = Path("data/source_facts_historical_retry.json")
LEDGER_VERSION = 1


def load_ledger(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return set()
    values = payload.get("item_ids", []) if isinstance(payload, dict) else []
    return {str(value).strip() for value in values if str(value).strip()}


def save_ledger(path: Path, item_ids: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": LEDGER_VERSION,
        "item_ids": sorted(item_ids),
    }
    path.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def candidate_pool(*, item_ids: set[str] | None = None) -> tuple[list, dict]:
    items = store.load_items()
    existing = store.load_source_facts()
    # On récupère tout le pool puis on applique le ledger avant la limite du run,
    # afin qu'une vieille abstention déjà retraitée ne bloque jamais les suivantes.
    return backfill.select_candidates(
        items,
        existing,
        item_ids=item_ids,
        max_items=max(1, len(items)),
    )


def run_guarded(
    *,
    max_items: int = DEFAULT_MAX_ITEMS,
    max_seconds: float = DEFAULT_MAX_SECONDS,
    item_ids: set[str] | None = None,
    dry_run: bool = False,
    ledger_path: Path = DEFAULT_LEDGER_PATH,
) -> dict:
    started = time.monotonic()
    ledger = load_ledger(ledger_path)
    pool, pool_metrics = candidate_pool(item_ids=item_ids)
    eligible = [item for item in pool if item.Item_ID not in ledger]
    selected = eligible[:max(0, max_items)]

    result = {
        "dry_run": dry_run,
        "max_items": max_items,
        "max_seconds": max_seconds,
        "pool_candidates": len(pool),
        "skipped_historical_retry": len(pool) - len(eligible),
        "eligible_candidates": len(eligible),
        "selected": len(selected),
        "selected_item_ids": [item.Item_ID for item in selected],
        "processed": 0,
        "summary_recovered": 0,
        "historical_retry_consumed": 0,
        "historical_retry_technical_restore": 0,
        "stopped_by_time_budget": False,
        "pool_metrics": pool_metrics,
    }
    if dry_run or not selected:
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        return result

    for index, item in enumerate(selected, start=1):
        elapsed = time.monotonic() - started
        if elapsed >= max_seconds:
            result["stopped_by_time_budget"] = True
            break

        print(
            f"SourceFacts guarded: item={index}/{len(selected)} "
            f"id={item.Item_ID} source={item.Source_ID} elapsed={elapsed:.1f}s",
            flush=True,
        )
        metrics = backfill.run_backfill(
            max_items=1,
            item_ids={item.Item_ID},
            dry_run=False,
            retry_abstained=True,
            retry_legacy_nulls=True,
        )
        result["processed"] += 1
        result["summary_recovered"] += int(metrics.get("summary_recovered") or 0)

        retried = set(metrics.get("abstained_retry_item_ids") or [])
        restored = int(metrics.get("abstained_retry_restored") or 0)
        if item.Item_ID in retried:
            if restored:
                # Une panne technique ne consomme pas l'unique retry historique.
                result["historical_retry_technical_restore"] += 1
            else:
                ledger.add(item.Item_ID)
                save_ledger(ledger_path, ledger)
                result["historical_retry_consumed"] += 1

        print(
            "SourceFacts guarded result: "
            + json.dumps(
                {
                    "item_id": item.Item_ID,
                    "summary_recovered": metrics.get("summary_recovered", 0),
                    "historical_retry": item.Item_ID in retried,
                    "technical_restore": bool(restored),
                    "elapsed_seconds": round(time.monotonic() - started, 1),
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            flush=True,
        )

    elapsed = time.monotonic() - started
    if result["processed"] < len(selected) and elapsed >= max_seconds:
        result["stopped_by_time_budget"] = True
    result["elapsed_seconds"] = round(elapsed, 3)
    result["remaining_selected"] = len(selected) - result["processed"]
    result["remaining_eligible"] = max(0, len(eligible) - result["processed"])
    return result


def _parse_item_ids(raw: str) -> set[str]:
    return {value.strip() for value in (raw or "").split(",") if value.strip()}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Exécute le backfill SourceFacts avec des garde-fous CI."
    )
    parser.add_argument("--max-items", type=int, default=DEFAULT_MAX_ITEMS)
    parser.add_argument("--max-seconds", type=float, default=DEFAULT_MAX_SECONDS)
    parser.add_argument("--item-ids", default="")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--ledger", default=str(DEFAULT_LEDGER_PATH))
    args = parser.parse_args()

    if args.max_items < 0:
        parser.error("--max-items doit être positif ou nul")
    if args.max_seconds <= 0:
        parser.error("--max-seconds doit être strictement positif")

    result = run_guarded(
        max_items=args.max_items,
        max_seconds=args.max_seconds,
        item_ids=_parse_item_ids(args.item_ids),
        dry_run=args.dry_run,
        ledger_path=Path(args.ledger),
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
