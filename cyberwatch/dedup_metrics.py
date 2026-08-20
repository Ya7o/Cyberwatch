"""Métriques reproductibles sur les décisions de déduplication effectivement appliquées."""

from __future__ import annotations

import csv
from collections import Counter, defaultdict
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
    "Left_Item_ID",
    "Right_Item_ID",
    "Organisation",
    "Left_Source",
    "Right_Source",
    "Left_Date",
    "Right_Date",
    "Days_Apart",
    "Reason_Code",
    "Left_Event_Date",
    "Right_Event_Date",
    "Left_Threat",
    "Right_Threat",
    "Left_Title",
    "Right_Title",
    "Left_URL",
    "Right_URL",
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


def applied_merge_decisions(items: list[Item]) -> list[tuple[Item, Item, DedupDecision]]:
    """Retourne une décision par item absorbé dans un composant final.

    `group_components` est ancré : chaque composant conserve son premier item
    comme ancre. Rejouer `decide_merge` entre cette ancre et les autres membres
    restitue donc les décisions positives qui ont effectivement produit le
    regroupement, sans compter toutes les comparaisons théoriques possibles.
    """
    rows: list[tuple[Item, Item, DedupDecision]] = []
    for component in group_components(items):
        if len(component) < 2:
            continue
        anchor = component[0]
        for member in component[1:]:
            decision = decide_merge(anchor, member)
            if decision.action == MERGE:
                rows.append((anchor, member, decision))
    return rows


def strong_veto_counts(items: list[Item]) -> Counter[str]:
    """Compte les veto forts paire à paire au sein d'une même identité victime."""
    by_org: dict[str, list[Item]] = defaultdict(list)
    for item in items:
        key = effective_organisation_key(item.Organisation_Raw, item.Organisation_Key)
        if key:
            by_org[key].append(item)

    counts: Counter[str] = Counter()
    for group in by_org.values():
        for left, right in combinations(group, 2):
            decision = decide_merge(left, right)
            if (
                decision.action == KEEP_SEPARATE
                and decision.reason_code in STRONG_KEEP_REASON_CODES
            ):
                counts[decision.reason_code] += 1
    return counts


def summarize_dedup(items: list[Item]) -> dict:
    components = group_components(items)
    merges = applied_merge_decisions(items)
    merge_reasons = Counter(_bucket_reason(decision) for _, _, decision in merges)
    vetoes = strong_veto_counts(items)
    incident_items = sum(len(component) for component in components)
    return {
        "items": len(items),
        "incident_items": incident_items,
        "incidents": len(components),
        "merged_items": len(merges),
        "merge_reasons": dict(sorted(merge_reasons.items())),
        "strong_veto_reasons": dict(sorted(vetoes.items())),
    }


def weak_merge_rows(items: list[Item]) -> list[dict[str, str]]:
    """Retourne uniquement les fusions faibles réellement appliquées."""
    rows: list[dict[str, str]] = []
    for left, right, decision in applied_merge_decisions(items):
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
    return sorted(
        rows,
        key=lambda row: (
            row["Reason_Code"],
            int(row["Days_Apart"] or 0),
            row["Organisation"],
            row["Left_Item_ID"],
            row["Right_Item_ID"],
        ),
    )


def write_weak_merges_csv(path: Path, items: list[Item]) -> int:
    rows = weak_merge_rows(items)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=WEAK_MERGE_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)
