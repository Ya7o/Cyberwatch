#!/usr/bin/env python3
"""Exporte les cas de déduplication à challenger, sans modifier la DB."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import dedup_ai
from cyberwatch.duplicate_audit import find_audit_candidates
from cyberwatch.model import Item
from cyberwatch.normalize import organisation_key


COLUMNS = [
    "Risk_Type",
    "Reason_Code",
    "Days_Apart",
    "Shared_Company_ID",
    "AI_Status",
    "AI_Same_Organisation",
    "AI_Same_Incident",
    "AI_Confidence",
    "AI_Evidence",
    "AI_Reason",
    "AI_Cache_Hit",
    "Left_Item_ID",
    "Left_Source_ID",
    "Left_Source_Item_ID",
    "Left_Date",
    "Left_Organisation",
    "Left_Organisation_Key",
    "Left_Company_ID",
    "Left_Title",
    "Left_URL",
    "Right_Item_ID",
    "Right_Source_ID",
    "Right_Source_Item_ID",
    "Right_Date",
    "Right_Organisation",
    "Right_Organisation_Key",
    "Right_Company_ID",
    "Right_Title",
    "Right_URL",
]


def load_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def load_company_ids(path: Path) -> dict[str, str]:
    """Charge uniquement les identités exactes déjà validées par le registre."""
    result: dict[str, str] = {}
    for row in load_rows(path):
        if row.get("Match_Status") != "MATCHED" or not row.get("Company_ID"):
            continue
        key = row.get("Organisation_Key", "")
        if key:
            result[key] = row["Company_ID"]
    return result


def company_id_for(item: Item, company_ids: dict[str, str]) -> str:
    return (
        company_ids.get(item.Organisation_Key, "")
        or company_ids.get(organisation_key(item.Organisation_Raw), "")
    )


def _candidate_key(candidate) -> tuple[str, str, str]:
    left_id, right_id = sorted((candidate.left.Item_ID, candidate.right.Item_ID))
    return candidate.risk_type, left_id, right_id


def export(
    items_path: Path,
    cache_path: Path,
    output_path: Path,
    *,
    ai_enabled: bool = False,
    source_facts_path: Path | None = None,
    ai_cache_path: Path | None = None,
) -> tuple[int, dedup_ai.DedupAiRunState | None]:
    items = [Item.from_row(row) for row in load_rows(items_path)]
    company_ids = load_company_ids(cache_path)
    candidates = find_audit_candidates(items, company_ids=company_ids)

    ai_state = None
    ai_decisions = {}
    if ai_enabled:
        facts_path = source_facts_path or ROOT / "data" / "source_facts.csv"
        dedup_cache = ai_cache_path or ROOT / "data" / "dedup_ai_cache.csv"
        facts = dedup_ai.load_source_facts(facts_path)
        ai_state = dedup_ai.start_run(dedup_cache)

        for candidate in sorted(candidates, key=dedup_ai.candidate_priority):
            left_company = company_id_for(candidate.left, company_ids)
            right_company = company_id_for(candidate.right, company_ids)
            ai_decisions[_candidate_key(candidate)] = dedup_ai.challenge_candidate(
                candidate,
                facts,
                ai_state,
                left_company_id=left_company,
                right_company_id=right_company,
            )
        dedup_ai.save_cache(ai_state)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        for candidate in candidates:
            left, right = candidate.left, candidate.right
            decision = ai_decisions.get(_candidate_key(candidate))
            writer.writerow({
                "Risk_Type": candidate.risk_type,
                "Reason_Code": candidate.reason_code,
                "Days_Apart": str(candidate.days_apart),
                "Shared_Company_ID": candidate.company_id,
                "AI_Status": decision.status if decision else "",
                "AI_Same_Organisation": decision.same_organisation if decision else "",
                "AI_Same_Incident": decision.same_incident if decision else "",
                "AI_Confidence": f"{decision.confidence:.4f}" if decision else "",
                "AI_Evidence": decision.evidence if decision else "",
                "AI_Reason": decision.reason if decision else "",
                "AI_Cache_Hit": "1" if decision and decision.cache_hit else "0" if decision else "",
                "Left_Item_ID": left.Item_ID,
                "Left_Source_ID": left.Source_ID,
                "Left_Source_Item_ID": left.Source_Item_ID,
                "Left_Date": left.best_date,
                "Left_Organisation": left.Organisation_Raw,
                "Left_Organisation_Key": left.Organisation_Key,
                "Left_Company_ID": company_id_for(left, company_ids),
                "Left_Title": left.Title,
                "Left_URL": left.URL,
                "Right_Item_ID": right.Item_ID,
                "Right_Source_ID": right.Source_ID,
                "Right_Source_Item_ID": right.Source_Item_ID,
                "Right_Date": right.best_date,
                "Right_Organisation": right.Organisation_Raw,
                "Right_Organisation_Key": right.Organisation_Key,
                "Right_Company_ID": company_id_for(right, company_ids),
                "Right_Title": right.Title,
                "Right_URL": right.URL,
            })
    return len(candidates), ai_state


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--items", default=str(ROOT / "data" / "items.csv"))
    parser.add_argument(
        "--org-cache",
        default=str(ROOT / "data" / "org_enrichment_cache.csv"),
    )
    parser.add_argument(
        "--output",
        default=str(ROOT / "data" / "dedup_audit_candidates.csv"),
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Challenge les candidats ambigus via une requête OpenAI classique, sans Search ni agent.",
    )
    parser.add_argument(
        "--source-facts",
        default=str(ROOT / "data" / "source_facts.csv"),
    )
    parser.add_argument(
        "--ai-cache",
        default=str(ROOT / "data" / "dedup_ai_cache.csv"),
    )
    args = parser.parse_args()

    total, state = export(
        Path(args.items),
        Path(args.org_cache),
        Path(args.output),
        ai_enabled=args.ai,
        source_facts_path=Path(args.source_facts),
        ai_cache_path=Path(args.ai_cache),
    )
    print(f"dedup_audit_candidates={total}")
    print(f"dedup_audit_output={args.output}")
    if state is not None:
        print(f"dedup_ai_enabled={int(state.enabled)}")
        print(f"dedup_ai_calls={state.calls_attempted}")
        print(f"dedup_ai_cache_hits={state.cache_hits}")
        print(f"dedup_ai_cost_usd={state.estimated_cost_usd:.6f}")


if __name__ == "__main__":
    main()
