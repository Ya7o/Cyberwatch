#!/usr/bin/env python3
"""Certifie la répétabilité de deux rebuilds dédup consécutifs.

Le premier rebuild peut normaliser un snapshot ancien. Le second doit être un
point fixe : aucune identité ni Item_ID ne change, et les sorties fonctionnelles
(hash incidents, métriques, weak merges, review queue) restent identiques.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REBUILD = ROOT / "scripts" / "rebuild_dedup.py"
AUDIT_FILES = (
    ROOT / "data" / "audit" / "dedup_weak_merges.csv",
    ROOT / "data" / "audit" / "dedup_review_queue.csv",
)
STABLE_AUDIT_FIELDS = (
    "items_after",
    "incidents_after",
    "incidents_hash_after",
    "dedup",
    "weak_merges",
    "possible_false_merges",
    "possible_missed_duplicates",
    "review_queue_rows",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run_rebuild() -> tuple[dict, dict[str, str]]:
    result = subprocess.run(
        [sys.executable, str(REBUILD)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise RuntimeError(f"rebuild failed with exit={result.returncode}")
    audit_line = next(
        (line for line in result.stdout.splitlines() if line.startswith("REBUILD_DEDUP_AUDIT ")),
        "",
    )
    if not audit_line:
        raise RuntimeError("missing REBUILD_DEDUP_AUDIT output")
    audit = json.loads(audit_line.split(" ", 1)[1])
    hashes = {str(path.relative_to(ROOT)): _sha256(path) for path in AUDIT_FILES}
    return audit, hashes


def main() -> int:
    first, first_hashes = _run_rebuild()
    second, second_hashes = _run_rebuild()

    failures: list[str] = []
    for field in STABLE_AUDIT_FIELDS:
        if first.get(field) != second.get(field):
            failures.append(f"{field}: first={first.get(field)!r} second={second.get(field)!r}")
    if first_hashes != second_hashes:
        failures.append(f"audit_file_hashes: first={first_hashes!r} second={second_hashes!r}")

    for field in ("organisation_keys_changed", "item_ids_changed", "items_collapsed_exact_duplicates"):
        if int(second.get(field, -1)) != 0:
            failures.append(f"second.{field}={second.get(field)!r} expected=0")

    payload = {
        "first": {field: first.get(field) for field in STABLE_AUDIT_FIELDS},
        "second": {field: second.get(field) for field in STABLE_AUDIT_FIELDS},
        "audit_file_hashes": second_hashes,
        "second_point_fix": {
            field: second.get(field)
            for field in ("organisation_keys_changed", "item_ids_changed", "items_collapsed_exact_duplicates")
        },
        "failures": failures,
    }
    print("DEDUP_CLOSEOUT=" + json.dumps(payload, ensure_ascii=False, sort_keys=True))
    if failures:
        print("DEDUP_CLOSEOUT_CERTIFIED=FAIL")
        return 1
    print("DEDUP_CLOSEOUT_CERTIFIED=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
