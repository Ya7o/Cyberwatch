"""Versioned, deterministic data-quality metrics and regression gates."""

from __future__ import annotations

from collections import defaultdict

from . import config, sector as sector_policy
from .model import Item


def _scope_metrics(rows: list[Item]) -> dict:
    total = len(rows)
    sector_unknown = sum(i.Sector == config.SECTOR_UNKNOWN for i in rows)
    organisation_keys = {i.Organisation_Key for i in rows if i.Organisation_Key}
    unknown_keys = {
        i.Organisation_Key
        for i in rows
        if i.Sector == config.SECTOR_UNKNOWN and i.Organisation_Key
    }
    unknown_occurrences: dict[str, int] = defaultdict(int)
    for item in rows:
        if item.Sector == config.SECTOR_UNKNOWN and item.Organisation_Key:
            unknown_occurrences[item.Organisation_Key] += 1

    result = {
        "items": total,
        "threat_unknown": sum(i.Threat == config.THREAT_UNKNOWN for i in rows),
        "sector_unknown": sector_unknown,
        "location_unknown": sum(i.Location == config.LOC_INCONNU for i in rows),
        "sector_known": total - sector_unknown,
        "sector_coverage_ratio": ((total - sector_unknown) / total if total else 0.0),
        "organisations": len(organisation_keys),
        "sector_unknown_organisations": len(unknown_keys),
        "sector_unknown_organisation_ratio": (
            len(unknown_keys) / len(organisation_keys) if organisation_keys else 0.0
        ),
        "sector_unknown_repeated_organisations": sum(
            count > 1 for count in unknown_occurrences.values()
        ),
        "sector_unknown_items_from_repeated_organisations": sum(
            count for count in unknown_occurrences.values() if count > 1
        ),
    }
    result.update(
        {
            f"{key}_ratio": (value / total if total else 0.0)
            for key, value in result.items()
            if key.endswith("_unknown")
        }
    )
    return result


def metrics(items: list[Item]) -> dict:
    groups: dict[str, list[Item]] = defaultdict(list)
    for item in items:
        groups[item.Source_ID].append(item)
    return {
        "global": _scope_metrics(items),
        "sources": {key: _scope_metrics(groups[key]) for key in sorted(groups)},
    }


def ransomware_source_sector_audit(
    items: list[Item], source_fact_rows: list[dict[str, str]]
) -> dict:
    """Mesure les opportunités de mapping du secteur structuré ransomware.live.

    ``Source_Sector_Raw`` est un fait structuré de la source, pas du texte libre.
    Le diagnostic sépare donc : absence de valeur brute, valeur déjà mappée par
    la taxonomie, et valeur brute encore non mappée. Aucune mutation n'est faite.
    """
    target = {
        item.Item_ID: item
        for item in items
        if item.Source_ID == "RANSOMWARE_LIVE"
    }
    facts = {
        row.get("Item_ID", ""): row
        for row in source_fact_rows
        if row.get("Source_ID") == "RANSOMWARE_LIVE" and row.get("Item_ID") in target
    }

    raw_values: dict[str, dict[str, object]] = {}
    unknown = 0
    unknown_with_raw = 0
    unknown_without_raw = 0
    unknown_raw_mappable = 0
    unknown_raw_unmapped = 0

    for item_id, item in target.items():
        is_unknown = item.Sector == config.SECTOR_UNKNOWN
        if is_unknown:
            unknown += 1
        raw = (facts.get(item_id, {}).get("Source_Sector_Raw") or "").strip()
        if not raw:
            if is_unknown:
                unknown_without_raw += 1
            continue

        mapped = sector_policy.classify_source_sector(raw)
        bucket = raw_values.setdefault(
            raw,
            {
                "items": 0,
                "current_unknown": 0,
                "mapped_sector": mapped,
            },
        )
        bucket["items"] = int(bucket["items"]) + 1
        if is_unknown:
            bucket["current_unknown"] = int(bucket["current_unknown"]) + 1
            unknown_with_raw += 1
            if mapped == config.SECTOR_UNKNOWN:
                unknown_raw_unmapped += 1
            else:
                unknown_raw_mappable += 1

    ordered_values = {
        raw: raw_values[raw]
        for raw in sorted(
            raw_values,
            key=lambda value: (
                -int(raw_values[value]["current_unknown"]),
                -int(raw_values[value]["items"]),
                value.lower(),
            ),
        )
    }
    return {
        "items": len(target),
        "current_unknown": unknown,
        "current_known": len(target) - unknown,
        "unknown_with_raw": unknown_with_raw,
        "unknown_without_raw": unknown_without_raw,
        "unknown_raw_mappable": unknown_raw_mappable,
        "unknown_raw_unmapped": unknown_raw_unmapped,
        "raw_values": ordered_values,
    }


def compare(current: dict, baseline: dict) -> list[str]:
    """Return regressions only for scopes whose item population is comparable.

    Absolute unknown counts are meaningful only when the scope contains the
    same number of items as the recorded baseline. A CREATE can legitimately
    change source depth or perimeter; comparing 395 current rows with 390 old
    rows would otherwise turn normal coverage changes into false regressions.

    Precision guards that do not depend on population size (deterministic
    threat candidates, actor sentinels, exact duplicate candidates) are
    enforced separately by ``scripts/audit_data_quality.py`` and remain hard
    blockers regardless of this comparison.
    """
    problems: list[str] = []
    for scope in ("global", *sorted(current.get("sources", {}))):
        now = current["global"] if scope == "global" else current["sources"][scope]
        old = (
            baseline.get("global", {})
            if scope == "global"
            else baseline.get("sources", {}).get(scope, {})
        )
        if not old or old.get("items") != now.get("items"):
            continue
        for field in ("threat_unknown", "sector_unknown", "location_unknown"):
            if field not in old:
                continue
            if now[field] > old[field]:
                problems.append(
                    f"quality regression {scope}: {field} absolute {old[field]} -> {now[field]}"
                )
    return problems
