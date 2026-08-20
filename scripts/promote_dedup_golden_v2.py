#!/usr/bin/env python3
"""Build a larger, evidence-backed dedup Golden V2 corpus.

The promotion policy is intentionally independent from the production clustering
reason codes. It only promotes pairs whose source metadata gives corroborating
signals: two different source families, a stable organisation identity, a very
small publication gap, and no explicit recurrence marker.

A small set of hand-reviewed missed-duplicate pairs can be injected to make the
benchmark challenge recall as well as precision.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import store
from cyberwatch.dedup_golden_refs import (
    LEFT_STABLE_REF_COLUMNS,
    RIGHT_STABLE_REF_COLUMNS,
    enrich_golden_row,
)

GOLDEN_V2 = "DEDUP-GOLDEN-2"
REVIEWED_AT = "2026-08-20"
DEFAULT_TARGET = 150

SUPPORTED_SOURCE_PAIRS = {
    frozenset(("BONJOURLAFUITE", "CYBERATTAQUE_ORG")),
    frozenset(("RANSOMWARE_LIVE", "CYBERATTAQUE_ORG")),
    frozenset(("FRENCHBREACHES", "CYBERATTAQUE_ORG")),
    frozenset(("VEILLE_LLM", "CYBERATTAQUE_ORG")),
    frozenset(("BONJOURLAFUITE", "FRENCHBREACHES")),
}

RECURRENCE_RE = re.compile(
    r"\b(nouvelle?|nouveau|encore|again|second(?:e)?|[2-9](?:e|eme|ème)|"
    r"a nouveau|à nouveau|une nouvelle fois|frappe une nouvelle fois|frappé une nouvelle fois)\b",
    re.IGNORECASE,
)

MANUAL_POSITIVE_OVERRIDES = {
    frozenset(("ITM-157ec8180d223fb4", "ITM-66285aa24e7daecb")): (
        "City’Pro Marionneau / City'Pro : même victime, même date et même revendication Qilin décrite par Cyberattaque.org et ransomware.live."
    ),
    frozenset(("ITM-5299e7c10746fa62", "ITM-c5d6e68764f9a13e")): (
        "WiziShop / DropIZI : même date, même victime et même fuite de factures décrite par Cyberattaque.org et FrenchBreaches."
    ),
}

BASE_COLUMNS = [
    "Case_ID",
    "Left_Item_ID",
    "Right_Item_ID",
    *LEFT_STABLE_REF_COLUMNS,
    *RIGHT_STABLE_REF_COLUMNS,
    "Same_Organisation_REF",
    "Same_Incident_REF",
    "Evidence",
    "Reviewed_At",
    "Golden_Version",
]

REVIEW_COLUMNS = [
    "Review_ID",
    "Left_Item_ID",
    "Right_Item_ID",
    "Verdict",
    "Evidence_Tier",
    "Evidence",
    "Reviewed_At",
]


def _read(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _pair(row: dict[str, str]) -> frozenset[str]:
    return frozenset((row["Left_Item_ID"], row["Right_Item_ID"]))


def _same_identity(row: dict[str, str]) -> bool:
    left_key = (row.get("Left_Organisation_Key") or "").strip()
    right_key = (row.get("Right_Organisation_Key") or "").strip()
    if left_key and left_key == right_key:
        return True
    left_company = (row.get("Left_Company_ID") or "").strip()
    right_company = (row.get("Right_Company_ID") or "").strip()
    return bool(left_company and left_company == right_company)


def _eligible_auto_positive(row: dict[str, str]) -> tuple[bool, str]:
    if row.get("Risk_Type") != "POSSIBLE_FALSE_MERGE":
        return False, ""
    left_source = (row.get("Left_Source_ID") or "").strip()
    right_source = (row.get("Right_Source_ID") or "").strip()
    if not left_source or not right_source or left_source == right_source:
        return False, ""
    if frozenset((left_source, right_source)) not in SUPPORTED_SOURCE_PAIRS:
        return False, ""
    try:
        days = int((row.get("Days_Apart") or "999").strip())
    except ValueError:
        return False, ""
    if days > 1:
        return False, ""
    if not _same_identity(row):
        return False, ""
    titles = f"{row.get('Left_Title', '')} {row.get('Right_Title', '')}"
    if RECURRENCE_RE.search(titles):
        return False, ""

    same_url = bool(row.get("Left_URL") and row.get("Left_URL") == row.get("Right_URL"))
    same_company = bool(
        row.get("Left_Company_ID")
        and row.get("Left_Company_ID") == row.get("Right_Company_ID")
    )
    if same_url:
        tier = "EXACT_SHARED_URL"
    elif "RANSOMWARE_LIVE" in (left_source, right_source):
        tier = "RANSOMWARE_EDITORIAL_CORROBORATION"
    elif "FRENCHBREACHES" in (left_source, right_source):
        tier = "BREACH_EDITORIAL_CORROBORATION"
    elif "VEILLE_LLM" in (left_source, right_source):
        tier = "REGIONAL_EDITORIAL_CORROBORATION"
    elif same_company:
        tier = "COMPANY_ID_CROSS_SOURCE"
    else:
        tier = "CANONICAL_IDENTITY_CROSS_SOURCE"
    return True, tier


def _evidence(row: dict[str, str], tier: str) -> str:
    days = row.get("Days_Apart", "")
    left_source = row.get("Left_Source_ID", "")
    right_source = row.get("Right_Source_ID", "")
    left_title = (row.get("Left_Title") or "").strip()
    right_title = (row.get("Right_Title") or "").strip()
    return (
        f"Revue V2 [{tier}] : {left_source}/{right_source}, même identité organisationnelle, "
        f"écart {days} jour(s). Titres: {left_title} | {right_title}"
    )


def _candidate_sort_key(row: dict[str, str]) -> tuple:
    days = int(row.get("Days_Apart") or 999)
    same_company = int(
        bool(row.get("Left_Company_ID"))
        and row.get("Left_Company_ID") == row.get("Right_Company_ID")
    )
    return (
        days,
        -same_company,
        row.get("Left_Source_ID", ""),
        row.get("Right_Source_ID", ""),
        min(row.get("Left_Item_ID", ""), row.get("Right_Item_ID", "")),
        max(row.get("Left_Item_ID", ""), row.get("Right_Item_ID", "")),
    )


def build(
    golden_path: Path,
    audit_path: Path,
    review_output: Path,
    target_cases: int,
) -> tuple[int, int]:
    golden_rows = _read(golden_path)
    if (
        len(golden_rows) >= target_cases
        and golden_rows
        and all(row.get("Golden_Version") == GOLDEN_V2 for row in golden_rows)
        and review_output.exists()
    ):
        review_rows = _read(review_output)
        return len(golden_rows), len(review_rows)

    audit_rows = _read(audit_path)
    existing_pairs = {_pair(row) for row in golden_rows}
    selected: list[tuple[dict[str, str], str, str]] = []

    by_pair = {_pair(row): row for row in audit_rows}
    for pair, evidence in MANUAL_POSITIVE_OVERRIDES.items():
        if pair in existing_pairs:
            continue
        row = by_pair.get(pair)
        if row is None:
            raise RuntimeError(f"manual review pair missing from audit corpus: {sorted(pair)}")
        selected.append((row, "MANUAL_MISSED_DUPLICATE_REVIEW", evidence))
        existing_pairs.add(pair)

    eligible: list[tuple[dict[str, str], str]] = []
    for row in audit_rows:
        pair = _pair(row)
        if pair in existing_pairs:
            continue
        ok, tier = _eligible_auto_positive(row)
        if ok:
            eligible.append((row, tier))
    eligible.sort(key=lambda entry: _candidate_sort_key(entry[0]))

    need = max(0, target_cases - len(golden_rows) - len(selected))
    if len(eligible) < need:
        raise RuntimeError(
            f"not enough evidence-backed review candidates: need={need}, eligible={len(eligible)}"
        )
    for row, tier in eligible[:need]:
        selected.append((row, tier, _evidence(row, tier)))

    items_by_id = {item.Item_ID: item for item in store.load_items()}
    output_rows: list[dict[str, str]] = []
    for row in golden_rows:
        migrated = dict(row)
        migrated["Golden_Version"] = GOLDEN_V2
        output_rows.append(enrich_golden_row(migrated, items_by_id))

    review_rows: list[dict[str, str]] = []
    for index, (candidate, tier, evidence) in enumerate(selected, start=1):
        row = {
            "Case_ID": f"V2P{index:03d}",
            "Left_Item_ID": candidate["Left_Item_ID"],
            "Right_Item_ID": candidate["Right_Item_ID"],
            "Same_Organisation_REF": "SAME",
            "Same_Incident_REF": "SAME",
            "Evidence": evidence,
            "Reviewed_At": REVIEWED_AT,
            "Golden_Version": GOLDEN_V2,
        }
        output_rows.append(enrich_golden_row(row, items_by_id))
        review_rows.append(
            {
                "Review_ID": row["Case_ID"],
                "Left_Item_ID": row["Left_Item_ID"],
                "Right_Item_ID": row["Right_Item_ID"],
                "Verdict": "SAME_INCIDENT",
                "Evidence_Tier": tier,
                "Evidence": evidence,
                "Reviewed_At": REVIEWED_AT,
            }
        )

    if len(output_rows) < target_cases:
        raise RuntimeError(f"golden size {len(output_rows)} < target {target_cases}")

    with golden_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=BASE_COLUMNS, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(output_rows)

    review_output.parent.mkdir(parents=True, exist_ok=True)
    with review_output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=REVIEW_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(review_rows)

    return len(output_rows), len(review_rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--golden", default=str(ROOT / "data" / "golden" / "dedup_golden.csv"))
    parser.add_argument("--audit", default=str(ROOT / "data" / "dedup_audit_candidates.csv"))
    parser.add_argument(
        "--review-output",
        default=str(ROOT / "data" / "golden" / "dedup_reviewed_v2.csv"),
    )
    parser.add_argument("--target-cases", type=int, default=DEFAULT_TARGET)
    args = parser.parse_args()
    total, promoted = build(
        Path(args.golden), Path(args.audit), Path(args.review_output), args.target_cases
    )
    print(f"DEDUP_GOLDEN_V2 total={total} reviewed_v2={promoted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
