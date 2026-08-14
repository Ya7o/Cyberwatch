#!/usr/bin/env python3
"""Retire explicitement des runs de validation des historiques opérationnels."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import store
from cyberwatch.model import RUN_LOG_COLUMNS, RUN_SOURCE_COLUMNS


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", action="append", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    target = set(args.run_id)
    logs = store.load_run_log()
    sources = store.load_run_sources()
    found = {row.get("Run_ID", "") for row in logs} & target
    missing = target - found
    if missing:
        parser.error("run(s) absent(s) : " + ", ".join(sorted(missing)))
    kept_logs = [row for row in logs if row.get("Run_ID", "") not in target]
    kept_sources = [row for row in sources if row.get("Run_ID", "") not in target]
    print(f"runs={','.join(sorted(target))}")
    print(f"run_log_removed={len(logs) - len(kept_logs)}")
    print(f"run_sources_removed={len(sources) - len(kept_sources)}")
    if not args.apply:
        print("dry_run=PASS")
        return 0
    store.write_csv(store.RUN_LOG_CSV, RUN_LOG_COLUMNS, kept_logs)
    store.write_csv(store.RUN_SOURCES_CSV, RUN_SOURCE_COLUMNS, kept_sources)
    print("apply=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
