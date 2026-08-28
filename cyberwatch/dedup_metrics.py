"""Métriques reproductibles sur les décisions de déduplication effectivement appliquées."""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from collections.abc import Mapping
from itertools import combinations
from pathlib import Path

from .dedup import (
    KEEP_SEPARATE,
    MERGE,
    STRONG_KEEP_REASON_CODES,
    DedupDecision,
    decide_merge,
    group_components,
)
from .model import Item
from .org_identity import effective_organisation_key

WEAK_MERGE_REASONS = frozenset({
    "INCIDENT_MERGE_CANONICAL_NAME",
    "INCIDENT_MERGE_ALIAS",
    "INCIDENT_MERGE_RANSOMWARE_CORROBORATION",
})

WEAK_MERGE_COLUMNS = [
    "Left_Item_ID", "Right_Item_ID", "Organisation", "Left_Source", "Right_Source",
    "Left_Date", "Right_Date", "Days_Apart", "Reason_Code", "Left_Event_Date",
    "Right_Event_Date", "Left_Threat", "Right_Threat", "Left_Title", "Right_Title",
    "Left_URL", "Right_URL",
]

RUN_HISTORY_COLUMNS = [
    "Run_At", "Items", "Incident_Items", "Incidents", "Merged_Items",
    "Candidate_Pairs", "Possible_False_Merges", "Possible_Missed_Duplicates",
    "Runtime_Seconds", "Incidents_Hash", "Merge_Reasons_JSON",
    "Strong_Veto_Reasons_JSON", "Decision_Reasons_JSON",
]

REVIEW_QUEUE_COLUMNS = [
    "Risk_Type", "Risk_Priority", "Reason_Code", "Days_Apart", "Company_ID",
    "Left_Item_ID", "Right_Item_ID", "Left_Source", "Right_Source", "Left_Date",
    "Right_Date", "Left_Organisation", "Right_Organisation", "Left_Threat",
    "Right_Threat", "Left_Title", "Right_Title", "Left_URL", "Right_URL",
]


def _days_signal(decision: DedupDecision) -> str:
    for signal in decision.signals:
        if signal.startswith("days="):
            return signal.split("=", 1)[1]
    return ""


def _bucket_reason(decision: DedupDecision) -> str:
    if decision.reason_code in WEAK_MERGE_REASONS:
        days = _days_signal(decision)
        if days:
            return f"{decision.reason_code}_J{days}"
    return decision.reason_code


def _by_org(items: list[Item]) -> dict[str, list[Item]]:
    grouped: dict[str, list[Item]] = defaultdict(list)
    for item in items:
        key = effective_organisation_key(item.Organisation_Raw, item.Organisation_Key)
        if key:
            grouped[key].append(item)
    return grouped


def applied_merge_decisions(
    items: list[Item],
    incident_decisions: Mapping[str, str] | None = None,
) -> list[tuple[Item, Item, DedupDecision]]:
    """Retourne un arbre de fusion explicatif pour chaque composante.

    Comparer seulement chaque membre à l'ancre sous-comptait les extensions
    valides via un membre intermédiaire. Un arbre couvrant rapporte exactement
    ``taille - 1`` fusions pour toute composante construite.
    """
    rows: list[tuple[Item, Item, DedupDecision]] = []
    for component in group_components(items, incident_decisions):
        if len(component) < 2:
            continue
        connected = [component[0]]
        remaining = list(component[1:])
        while remaining:
            candidates = []
            for left in connected:
                for right in remaining:
                    decision = decide_merge(left, right, incident_decisions)
                    if decision.action == MERGE:
                        candidates.append((left.Item_ID, right.Item_ID, left, right, decision))
            if not candidates:
                break
            _, _, left, right, decision = min(candidates, key=lambda row: row[:2])
            rows.append((left, right, decision))
            connected.append(right)
            remaining.remove(right)
    return rows


def candidate_pair_count(items: list[Item]) -> int:
    """Nombre de paires comparables au sein d'une même identité victime."""
    return sum(len(group) * (len(group) - 1) // 2 for group in _by_org(items).values())


def decision_reason_counts(
    items: list[Item],
    incident_decisions: Mapping[str, str] | None = None,
) -> Counter[str]:
    """Distribution exhaustive des décisions paire à paire intra-organisation."""
    counts: Counter[str] = Counter()
    for group in _by_org(items).values():
        for left, right in combinations(group, 2):
            counts[_bucket_reason(decide_merge(left, right, incident_decisions))] += 1
    return counts


def strong_veto_counts(
    items: list[Item],
    incident_decisions: Mapping[str, str] | None = None,
) -> Counter[str]:
    counts: Counter[str] = Counter()
    for group in _by_org(items).values():
        for left, right in combinations(group, 2):
            decision = decide_merge(left, right, incident_decisions)
            if decision.action == KEEP_SEPARATE and decision.reason_code in STRONG_KEEP_REASON_CODES:
                counts[decision.reason_code] += 1
    return counts


def summarize_dedup(
    items: list[Item],
    incident_decisions: Mapping[str, str] | None = None,
) -> dict:
    components = group_components(items, incident_decisions)
    merges = applied_merge_decisions(items, incident_decisions)
    merge_reasons = Counter(_bucket_reason(decision) for _, _, decision in merges)
    vetoes = strong_veto_counts(items, incident_decisions)
    decisions = decision_reason_counts(items, incident_decisions)
    incident_items = sum(len(component) for component in components)
    return {
        "items": len(items),
        "incident_items": incident_items,
        "incidents": len(components),
        "merged_items": incident_items - len(components),
        "candidate_pairs": candidate_pair_count(items),
        "merge_reasons": dict(sorted(merge_reasons.items())),
        "strong_veto_reasons": dict(sorted(vetoes.items())),
        "decision_reasons": dict(sorted(decisions.items())),
    }


def weak_merge_rows(
    items: list[Item],
    incident_decisions: Mapping[str, str] | None = None,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for left, right, decision in applied_merge_decisions(items, incident_decisions):
        if decision.reason_code not in WEAK_MERGE_REASONS:
            continue
        rows.append({
            "Left_Item_ID": left.Item_ID,
            "Right_Item_ID": right.Item_ID,
            "Organisation": left.Organisation_Raw or right.Organisation_Raw,
            "Left_Source": left.Source_ID,
            "Right_Source": right.Source_ID,
            "Left_Date": left.best_date,
            "Right_Date": right.best_date,
            "Days_Apart": _days_signal(decision),
            "Reason_Code": decision.reason_code,
            "Left_Event_Date": left.Event_Date,
            "Right_Event_Date": right.Event_Date,
            "Left_Threat": left.Threat,
            "Right_Threat": right.Threat,
            "Left_Title": left.Title,
            "Right_Title": right.Title,
            "Left_URL": left.URL,
            "Right_URL": right.URL,
        })
    return sorted(rows, key=lambda row: (
        row["Reason_Code"], int(row["Days_Apart"] or 0), row["Organisation"],
        row["Left_Item_ID"], row["Right_Item_ID"],
    ))


def write_weak_merges_csv(
    path: Path,
    items: list[Item],
    incident_decisions: Mapping[str, str] | None = None,
) -> int:
    rows = weak_merge_rows(items, incident_decisions)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=WEAK_MERGE_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def _review_priority(risk_type: str, reason_code: str, days_apart: int) -> int:
    """Priorité déterministe : faux merge > miss, puis règles faibles éloignées."""
    if risk_type == "POSSIBLE_FALSE_MERGE":
        if "RANSOMWARE" in reason_code:
            return 100
        return 90 + min(days_apart, 9)
    if "SHARED_COMPANY_ID" in reason_code:
        return 70
    return 50 + min(days_apart, 9)


def review_queue_rows(items: list[Item], company_ids: dict[str, str] | None = None) -> list[dict[str, str]]:
    from .duplicate_audit import find_audit_candidates

    rows: list[dict[str, str]] = []
    for candidate in find_audit_candidates(items, company_ids=company_ids):
        left, right = candidate.left, candidate.right
        rows.append({
            "Risk_Type": candidate.risk_type,
            "Risk_Priority": str(_review_priority(candidate.risk_type, candidate.reason_code, candidate.days_apart)),
            "Reason_Code": candidate.reason_code,
            "Days_Apart": str(candidate.days_apart),
            "Company_ID": candidate.company_id,
            "Left_Item_ID": left.Item_ID,
            "Right_Item_ID": right.Item_ID,
            "Left_Source": left.Source_ID,
            "Right_Source": right.Source_ID,
            "Left_Date": left.best_date,
            "Right_Date": right.best_date,
            "Left_Organisation": left.Organisation_Raw,
            "Right_Organisation": right.Organisation_Raw,
            "Left_Threat": left.Threat,
            "Right_Threat": right.Threat,
            "Left_Title": left.Title,
            "Right_Title": right.Title,
            "Left_URL": left.URL,
            "Right_URL": right.URL,
        })
    return sorted(rows, key=lambda row: (
        -int(row["Risk_Priority"]), row["Risk_Type"], row["Left_Date"],
        row["Left_Item_ID"], row["Right_Item_ID"],
    ))


def write_review_queue_csv(path: Path, items: list[Item], company_ids: dict[str, str] | None = None) -> int:
    rows = review_queue_rows(items, company_ids=company_ids)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=REVIEW_QUEUE_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def append_run_history(
    path: Path,
    *,
    run_at: str,
    summary: dict,
    runtime_seconds: float,
    incidents_hash: str,
    possible_false_merges: int,
    possible_missed_duplicates: int,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists() and path.stat().st_size > 0
    row = {
        "Run_At": run_at,
        "Items": summary["items"],
        "Incident_Items": summary["incident_items"],
        "Incidents": summary["incidents"],
        "Merged_Items": summary["merged_items"],
        "Candidate_Pairs": summary["candidate_pairs"],
        "Possible_False_Merges": possible_false_merges,
        "Possible_Missed_Duplicates": possible_missed_duplicates,
        "Runtime_Seconds": f"{runtime_seconds:.6f}",
        "Incidents_Hash": incidents_hash,
        "Merge_Reasons_JSON": json.dumps(summary["merge_reasons"], ensure_ascii=False, sort_keys=True),
        "Strong_Veto_Reasons_JSON": json.dumps(summary["strong_veto_reasons"], ensure_ascii=False, sort_keys=True),
        "Decision_Reasons_JSON": json.dumps(summary["decision_reasons"], ensure_ascii=False, sort_keys=True),
    }
    with path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=RUN_HISTORY_COLUMNS)
        if not exists:
            writer.writeheader()
        writer.writerow(row)
