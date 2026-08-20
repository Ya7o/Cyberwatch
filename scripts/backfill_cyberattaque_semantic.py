#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

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
