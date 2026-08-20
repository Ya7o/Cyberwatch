#!/usr/bin/env python3
"""Exporte les décisions de déduplication les plus risquées à revoir."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import store
from cyberwatch.dedup_metrics import write_review_queue_csv


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default=str(ROOT / "data" / "audit" / "dedup_review_queue.csv"),
    )
    args = parser.parse_args()
    count = write_review_queue_csv(Path(args.output), store.load_items())
    print(f"DEDUP_REVIEW_QUEUE_ROWS={count} output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
