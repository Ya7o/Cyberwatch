#!/usr/bin/env python3
"""Évalue les critères de clôture Performance/Incrémental à partir des runs réels."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import incremental_performance
from cyberwatch.performance_gates import validate_history


def format_duration(value) -> str:
    seconds = float(value or 0)
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    return f"{minutes}m{int(round(seconds % 60)):02d}s"


def main() -> int:
    rows = incremental_performance._load_performance_history()
    if not rows:
        print("PERFORMANCE_CLOSEOUT=NOT_READY reason=no_real_runs")
        return 0
    recent = rows[-10:]
    errors = validate_history(recent)
    delta = [r for r in recent if r.get("qualification_mode") == "delta"]
    changed = [r for r in recent if int(r.get("prequal_new") or 0) or int(r.get("prequal_dirty") or 0)]
    latest = recent[-1]
    print(
        "PERFORMANCE_CLOSEOUT_SUMMARY "
        f"runs={len(recent)} delta_runs={len(delta)} changed_runs={len(changed)} "
        f"latest={format_duration(latest.get('duration_s'))} "
        f"gate_errors={len(errors)}"
    )
    if errors:
        print("PERFORMANCE_CLOSEOUT=BLOCKED")
        for error in errors[:20]:
            print(f"- {error}")
        return 1
    # Le code peut être clôturé sans inventer des mesures : le verdict READY
    # exige au moins un run réel ayant emprunté le fast-path.
    if not delta:
        print("PERFORMANCE_CLOSEOUT=NOT_READY reason=no_real_delta_run")
        return 0
    print("PERFORMANCE_CLOSEOUT=READY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
