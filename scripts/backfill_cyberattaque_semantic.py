#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# A script launched as ``python scripts/foo.py`` gets ``scripts/`` on sys.path,
# not the repository root. Bootstrap the root so direct CLI execution works in
# GitHub Actions and locally without relying on an external PYTHONPATH.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch.cyberattaque_semantic_backfill import DEFAULT_ENDPOINT, run


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--start", default="2026-01-01")
    parser.add_argument("--max-calls", type=int, default=int(os.getenv("CYBERATTAQUE_SEMANTIC_MAX_CALLS_PER_RUN", "30") or 30))
    parser.add_argument("--http-timeout", type=int, default=30)
    parser.add_argument("--progress", default="data/quality/cyberattaque_semantic_progress.json")
    parser.add_argument("--backlog", default="data/quality/cyberattaque_semantic_backlog.json")
    args = parser.parse_args()
    stats = run(
        endpoint=args.endpoint,
        start=args.start,
        max_calls=args.max_calls,
        http_timeout=args.http_timeout,
        progress_path=Path(args.progress),
        backlog_path=Path(args.backlog),
    )
    print(json.dumps(stats, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
