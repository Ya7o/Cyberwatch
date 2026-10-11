"""Réouvre les reprises épuisées par une indisponibilité prouvée du provider."""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import store


def recover_provider_failures(rows: list[dict], root: Path | None = None) -> list[dict]:
    archived: dict[str, bool] = {}
    result: list[dict] = []
    for raw in rows:
        row = dict(raw)
        run_id = str(row.get("last_run") or "")
        if row.get("status") == "RETRY_EXHAUSTED" and re.fullmatch(r"RUN-[A-Za-z0-9_-]+", run_id):
            if run_id not in archived:
                try:
                    path = (root or store.DATA_DIR) / "llm_runs" / run_id / "llm_usage.json"
                    usage = json.loads(path.read_text())
                except (OSError, ValueError):
                    usage = {}
                usage = usage if isinstance(usage, dict) else {}
                try:
                    count = int(usage.get("calls_attempted") or 0)
                except (TypeError, ValueError):
                    count = 0
                tasks = usage.get("by_task")
                dedup_usage = tasks.get("dedup") if isinstance(tasks, dict) else None
                archived[run_id] = bool(count and count == usage.get("calls_failed")
                                        and count == usage.get("http_429")
                                        and not usage.get("calls_succeeded")
                                        and isinstance(dedup_usage, dict) and dedup_usage.get("calls_failed"))
            if archived[run_id]:
                row.update(status="ERROR", attempts=0, reason="PROVIDER_HTTP_429",
                           attempts_before_transport_recovery=row.get("attempts", 0))
        result.append(row)
    return result
