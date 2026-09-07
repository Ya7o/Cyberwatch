"""Audit reproductible de la résolution sectorielle du snapshot courant."""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = ROOT / "audit" / "sector_baseline_2026-09-01.json"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

def _pct(value: int, total: int) -> float:
    return round(100.0 * value / total, 2) if total else 0.0


def build_audit() -> dict:
    from cyberwatch import config, store
    from cyberwatch.normalize import organisation_key

    items = store.load_items()
    incidents = store.load_incidents()
    facts = {row.get("Item_ID", ""): row for row in store.load_source_facts()}
    decisions = store.load_sector_resolution()
    decision_by_item = {row.get("Item_ID", ""): row for row in decisions}

    unknown_items = [item for item in items if item.Sector == config.SECTOR_UNKNOWN]
    unknown_incidents = [incident for incident in incidents if incident.Secteur == config.SECTOR_UNKNOWN]
    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8")) if BASELINE_PATH.exists() else {}
    baseline_item_ids = set(baseline.get("unknown_item_ids", []))
    before_unknown = [row for row in decisions if row.get("Item_ID") in baseline_item_ids]
    evidence_gaps: Counter[str] = Counter()
    item_logs = []
    audit_items = [item for item in items if item.Item_ID in baseline_item_ids] or unknown_items
    for item in audit_items:
        fact = facts.get(item.Item_ID, {})
        if not str(fact.get("Source_Sector_Raw") or "").strip():
            evidence_gaps["source_sector_raw_absent"] += 1
        if not str(fact.get("Activity_Description") or "").strip():
            evidence_gaps["activity_description_absent"] += 1
        if not str(fact.get("Activity_Sector_Match") or "").strip():
            evidence_gaps["activity_sector_match_absent"] += 1
        decision = decision_by_item.get(item.Item_ID, {})
        item_logs.append({
            "item_id": item.Item_ID,
            "organisation": item.Organisation_Raw,
            "source": item.Source_ID,
            "title": item.Title,
            "source_sector_raw": fact.get("Source_Sector_Raw", ""),
            "activity_description": fact.get("Activity_Description", ""),
            "activity_sector_match": fact.get("Activity_Sector_Match", ""),
            "resolved_sector": decision.get("Resolved_Sector", item.Sector),
            "status": decision.get("Status", "unresolved"),
            "reason": decision.get("Reason", "NO_DECISION"),
            "confidence": decision.get("Confidence", ""),
            "evidence": decision.get("Evidence", ""),
            "evidence_url": decision.get("Evidence_URL", ""),
        })

    statuses = Counter(row.get("Status") or "missing" for row in decisions)
    reasons = Counter(row.get("Reason") or "missing" for row in decisions)
    return {
        "snapshot": {
            "items": len(items),
            "incidents": len(incidents),
            "unknown_items_after": len(unknown_items),
            "unknown_items_after_pct": _pct(len(unknown_items), len(items)),
            "unknown_incidents_after": len(unknown_incidents),
            "unknown_incidents_after_pct": _pct(len(unknown_incidents), len(incidents)),
            "unknown_items_before_resolution": len(before_unknown),
            "unknown_incidents_before_resolution": len(baseline.get("unknown_incidents", [])),
            "unknown_incidents_before_pct": _pct(
                len(baseline.get("unknown_incidents", [])), int(baseline.get("incidents_total", 0))
            ),
        },
        "root_causes": {
            "evidence_gaps_on_initially_unknown_items": dict(sorted(evidence_gaps.items())),
            "pipeline_gap": (
                "Les faits sectoriels auxiliaires étaient stockés dans source_facts.csv "
                "mais aucun consommateur ne les réinjectait dans Item.Sector."
            ),
            "policy_gap": (
                "L'absence de preuve et les contradictions doivent rester explicites ; "
                "un repli générique masque les défauts d'extraction et de transmission."
            ),
        },
        "resolution": {
            "statuses": dict(sorted(statuses.items())),
            "reasons": dict(sorted(reasons.items())),
            "target_pct": 10.0,
            "target_met": _pct(len(unknown_incidents), len(incidents)) < 10.0,
        },
        "items_initially_unknown": sorted(
            item_logs,
            key=lambda row: (organisation_key(row["organisation"]), row["item_id"]),
        ),
    }


def main() -> int:
    print(json.dumps(build_audit(), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
