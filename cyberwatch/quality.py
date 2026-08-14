"""Versioned, deterministic data-quality metrics and regression gates."""

from __future__ import annotations

from collections import defaultdict

from . import config
from .model import Item


def metrics(items: list[Item]) -> dict:
    def one(rows: list[Item]) -> dict:
        total = len(rows)
        result = {
            "items": len(rows),
            "threat_unknown": sum(i.Threat == config.THREAT_UNKNOWN for i in rows),
            "sector_unknown": sum(i.Sector == config.SECTOR_UNKNOWN for i in rows),
            "location_unknown": sum(i.Location == config.LOC_INCONNU for i in rows),
        }
        result.update({f"{key}_ratio": (value / total if total else 0.0) for key, value in result.items() if key.endswith("_unknown")})
        return result
    groups: dict[str, list[Item]] = defaultdict(list)
    for item in items:
        groups[item.Source_ID].append(item)
    return {"global": one(items), "sources": {key: one(groups[key]) for key in sorted(groups)}}


def compare(current: dict, baseline: dict) -> list[str]:
    """Return regressions for comparable scopes, with absolute counts primary."""
    problems: list[str] = []
    for scope in ("global", *sorted(current.get("sources", {}))):
        now = current["global"] if scope == "global" else current["sources"][scope]
        old = baseline.get("global", {}) if scope == "global" else baseline.get("sources", {}).get(scope, {})
        for field in ("threat_unknown", "sector_unknown", "location_unknown"):
            if field not in old:
                continue
            if now[field] > old[field]:
                problems.append(f"quality regression {scope}: {field} absolute {old[field]} -> {now[field]}")
            # A ratio is diagnostic only when the item population did not
            # change; otherwise a perimeter change makes it non-comparable.
            ratio = f"{field}_ratio"
            if old.get("items") == now.get("items") and ratio in old and now.get(ratio, 0) > old[ratio]:
                problems.append(f"quality regression {scope}: {field} ratio {old[ratio]:.4f} -> {now[ratio]:.4f}")
    return problems
