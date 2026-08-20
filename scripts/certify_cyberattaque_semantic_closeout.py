#!/usr/bin/env python3
"""Verdict opérationnel de clôture du backfill sémantique Cyberattaque.org."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def evaluate(progress: dict, certification: dict) -> dict:
    backlog = int(progress.get("backlog_remaining") or 0)
    failed = int(progress.get("failed_retryable") or 0)
    pending = int(progress.get("pending") or 0)
    certified = bool(certification.get("certified"))
    checks = {
        "progress_present": bool(progress),
        "certification_present": bool(certification),
        "semantic_certified": certified,
        "backlog_empty": backlog == 0,
        "pending_empty": pending == 0,
        "failed_retryable_empty": failed == 0,
    }
    ready = all(checks.values())
    reasons = [name for name, ok in checks.items() if not ok]
    return {
        "ready": ready,
        "status": "READY" if ready else "NOT_READY",
        "checks": checks,
        "reasons": reasons,
        "backlog_remaining": backlog,
        "pending": pending,
        "failed_retryable": failed,
        "llm_calls": int(progress.get("llm_calls") or 0),
        "cache_hits": int(progress.get("cache_hits") or 0),
        "updated": int(progress.get("updated") or 0),
        "duration_s": float(progress.get("duration_s") or 0),
    }


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--progress", default="data/quality/cyberattaque_semantic_progress.json")
    parser.add_argument("--certification", default="data/quality/cyberattaque_rich_certification.json")
    parser.add_argument("--json", dest="json_path", default="data/quality/cyberattaque_semantic_closeout.json")
    parser.add_argument("--allow-not-ready", action="store_true")
    args = parser.parse_args()

    result = evaluate(load_json(Path(args.progress)), load_json(Path(args.certification)))
    text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
    print(f"CYBERATTAQUE_SEMANTIC_CLOSEOUT={result['status']}")
    print(text)
    if args.json_path:
        target = Path(args.json_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text + "\n", encoding="utf-8")
    if not result["ready"] and not args.allow_not_ready:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
