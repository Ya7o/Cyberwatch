#!/usr/bin/env python3
"""Matérialise et compare le benchmark LLM Cyberattaque.org.

Le benchmark est volontairement stocké de façon compacte : toutes les lignes
non listées dans ``overrides`` ont été relues et leur ``Organisation_Raw`` de la
baseline épinglée a été acceptée. Ce script reconstruit donc les 408 décisions
explicites sans nouvelle passe LLM.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REFERENCE = ROOT / "tests/fixtures/cyberattaque_org_llm_reference_2026-08-14.json"


def _baseline_csv(commit: str) -> str:
    proc = subprocess.run(
        ["git", "show", f"{commit}:data/items.csv"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode:
        raise SystemExit(
            f"Impossible de lire data/items.csv au commit {commit}: {proc.stderr.strip()}"
        )
    return proc.stdout


def materialize(reference_path: Path) -> list[dict[str, str]]:
    reference = json.loads(reference_path.read_text(encoding="utf-8"))
    baseline = list(csv.DictReader(io.StringIO(_baseline_csv(reference["baseline_commit"]))))
    baseline = [row for row in baseline if row.get("Source_ID") == reference["source_id"]]
    if len(baseline) != reference["baseline_items"]:
        raise SystemExit(
            f"Baseline inattendue: {len(baseline)} items, attendu {reference['baseline_items']}"
        )

    overrides = {str(row["source_item_id"]): row for row in reference["overrides"]}
    seen_overrides: set[str] = set()
    rows: list[dict[str, str]] = []

    for row in baseline:
        source_item_id = str(row.get("Source_Item_ID", ""))
        override = overrides.get(source_item_id)
        if override:
            seen_overrides.add(source_item_id)
            llm_org = override["organisation"]
            status = override["status"]
            confidence = override["confidence"]
            reason = override["reason"]
        else:
            llm_org = row.get("Organisation_Raw", "")
            default = reference["default_for_unlisted_baseline_items"]
            status = default["status"]
            confidence = default["confidence"]
            reason = "Baseline relue et acceptée par le benchmark LLM."

        rows.append(
            {
                "Source_Item_ID": source_item_id,
                "Published_Date": row.get("Published_Date", ""),
                "Title": row.get("Title", ""),
                "URL": row.get("URL", ""),
                "Baseline_Organisation": row.get("Organisation_Raw", ""),
                "LLM_Organisation": llm_org,
                "LLM_Status": status,
                "LLM_Confidence": confidence,
                "LLM_Reason": reason,
            }
        )

    missing = sorted(set(overrides) - seen_overrides)
    if missing:
        raise SystemExit(f"Overrides absents de la baseline: {', '.join(missing)}")

    for extra in reference.get("additional_articles", []):
        rows.append(
            {
                "Source_Item_ID": str(extra.get("source_item_id", "")),
                "Published_Date": extra.get("published_date", ""),
                "Title": extra.get("title", ""),
                "URL": extra.get("url", ""),
                "Baseline_Organisation": "",
                "LLM_Organisation": extra.get("organisation", ""),
                "LLM_Status": extra.get("status", ""),
                "LLM_Confidence": extra.get("confidence", ""),
                "LLM_Reason": extra.get("reason", ""),
            }
        )

    if len(rows) != reference["source_articles_reviewed"]:
        raise SystemExit(
            f"Référence incomplète: {len(rows)} lignes, attendu {reference['source_articles_reviewed']}"
        )
    return rows


def _key(row: dict[str, str]) -> tuple[str, str]:
    source_item_id = str(row.get("Source_Item_ID", ""))
    if source_item_id:
        return ("id", source_item_id)
    return ("url", row.get("URL", ""))


def compare(rows: list[dict[str, str]], deterministic_path: Path) -> int:
    deterministic = list(csv.DictReader(deterministic_path.open(encoding="utf-8", newline="")))
    deterministic = [row for row in deterministic if not row.get("Source_ID") or row.get("Source_ID") == "CYBERATTAQUE_ORG"]
    by_key = {_key(row): row for row in deterministic}

    mismatches = 0
    for expected in rows:
        actual = by_key.get(_key(expected))
        actual_org = "" if actual is None else actual.get("Organisation_Raw", actual.get("Organisation", ""))
        if actual_org != expected["LLM_Organisation"]:
            mismatches += 1
            print(
                f"DIFF\t{expected['Source_Item_ID']}\t{expected['Title']}\t"
                f"det={actual_org!r}\tllm={expected['LLM_Organisation']!r}\t"
                f"status={expected['LLM_Status']}\tconfidence={expected['LLM_Confidence']}"
            )
    print(f"comparison_rows={len(rows)}; mismatches={mismatches}")
    return mismatches


def write_csv(rows: list[dict[str, str]], output: io.TextIOBase) -> None:
    writer = csv.DictWriter(output, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, default=DEFAULT_REFERENCE)
    parser.add_argument("--output", type=Path, help="Écrit les 408 décisions LLM en CSV.")
    parser.add_argument("--compare", type=Path, help="Compare avec un export déterministe CSV.")
    args = parser.parse_args()

    rows = materialize(args.reference)
    if args.output:
        with args.output.open("w", encoding="utf-8", newline="") as handle:
            write_csv(rows, handle)
        print(f"wrote={args.output}; rows={len(rows)}")
    elif not args.compare:
        write_csv(rows, sys.stdout)

    if args.compare:
        compare(rows, args.compare)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
