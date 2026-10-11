"""Résultats GitHub de COLLECT, y compris les échecs avant publication."""
from __future__ import annotations

import json

from . import store


def completed_scheduled_runs(run_log: list[dict]) -> list[dict] | None:
    starts = [str(row.get("As_Of") or "")[:10] for row in run_log
              if row.get("Trigger") == "schedule" and row.get("As_Of")]
    if not starts:
        return None
    try:
        payload = json.loads((store.DATA_DIR / "collection_workflow_runs.json").read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(payload, list):
        return None
    rows = [row for row in payload if isinstance(row, dict)
            and row.get("event") == "schedule" and row.get("status") == "completed"
            and str(row.get("created_at") or "")[:10] >= min(starts)]
    if not rows:
        return None
    return [{"Overall_Status": "OK" if row.get("conclusion") == "success" else "FAIL"}
            for row in sorted(rows, key=lambda row: (str(row.get("created_at")), str(row.get("id"))))]
