"""Reprise auditée secteur + doublons, vers une sortie séparée par défaut."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cyberwatch import (  # noqa: E402
    config, dedup, enrichment, incident_dedup, org_identity, sector_repair,
    sector_resolution, store,
)
from cyberwatch.collectors.feed import (  # noqa: E402
    explicit_frenchbreaches_victim, stable_frenchbreaches_detail_text,
)
from cyberwatch.identity import incidents_hash, items_hash  # noqa: E402
from cyberwatch.model import (  # noqa: E402
    DEDUP_AI_DAILY_USAGE_COLUMNS, INCIDENT_COLUMNS, ITEM_COLUMNS, SECTOR_RESOLUTION_COLUMNS,
    SOURCE_FACT_COLUMNS, Incident, Item,
)
from cyberwatch.normalize import organisation_key, searchable  # noqa: E402
from cyberwatch.sector import classify_sector_activity  # noqa: E402
from cyberwatch.sector_activity import activity_from_text  # noqa: E402


def _load_json(path: Path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def _archive_facts(items: list[Item], facts: list[dict], archive: Path) -> tuple[list[str], list[dict]]:
    by_fact = {row.get("Item_ID"): row for row in facts}
    updated, entity_candidates = [], []
    for item in items:
        path = archive / f"{item.Item_ID}.html"
        fact = by_fact.get(item.Item_ID)
        if fact is None or not path.exists() or item.Source_ID != "FRENCHBREACHES":
            continue
        text = stable_frenchbreaches_detail_text(path.read_text(encoding="utf-8"))
        victim = explicit_frenchbreaches_victim(text)
        if victim:
            changed = organisation_key(victim) != organisation_key(item.Organisation_Raw)
            entity_candidates.append({
                "item_id": item.Item_ID, "before": item.Organisation_Raw,
                "explicit_victim": victim,
                "action": "APPLIED_EXPLICIT_SOURCE_SUBJECT" if changed else "ALREADY_APPLIED",
            })
            if changed:
                item.Organisation_Raw = victim
                item.Organisation_Key = organisation_key(victim)
        activity, proof = activity_from_text(item.Organisation_Raw, text)
        sector = classify_sector_activity(activity)
        if not activity or sector == config.SECTOR_UNKNOWN:
            continue
        evidence = _load_json_value(fact.get("Evidence_JSON"))
        metadata = _load_json_value(fact.get("Source_Metadata_JSON"))
        fact["Activity_Description"] = activity
        fact["Activity_Sector_Match"] = sector
        evidence.update(Activity_Description=proof, Activity_Sector_Match=proof)
        metadata["_sector_backfill"] = {
            "method": "ARCHIVED_EDITORIAL_BODY", "policy": sector_resolution.POLICY_VERSION,
            "archive": path.name,
        }
        fact["Evidence_JSON"] = json.dumps(evidence, ensure_ascii=False, sort_keys=True)
        fact["Source_Metadata_JSON"] = json.dumps(metadata, ensure_ascii=False, sort_keys=True)
        updated.append(item.Item_ID)
    return updated, entity_candidates


def _reviewed_sector_facts(items: list[Item], facts: list[dict], reviews: list[dict]) -> list[str]:
    by_item = {item.Item_ID: item for item in items}
    by_fact = {row.get("Item_ID"): row for row in facts}
    updated = []
    for review in reviews:
        item, fact = by_item.get(review.get("item_id")), by_fact.get(review.get("item_id"))
        if item is None or fact is None:
            raise ValueError(f"Item de reprise sectorielle absent : {review.get('item_id')}")
        activity, sector = str(review.get("activity") or ""), str(review.get("sector") or "")
        if classify_sector_activity(activity) != sector or sector == config.SECTOR_UNKNOWN:
            raise ValueError(f"Décision sectorielle incohérente : {item.Item_ID}")
        if searchable(item.Organisation_Raw) not in searchable(activity):
            raise ValueError(f"Preuve sectorielle non liée à la victime : {item.Item_ID}")
        evidence = _load_json_value(fact.get("Evidence_JSON"))
        metadata = _load_json_value(fact.get("Source_Metadata_JSON"))
        fact["Activity_Description"] = activity
        fact["Activity_Sector_Match"] = sector
        evidence.update(Activity_Description=activity, Activity_Sector_Match=activity)
        metadata["_sector_backfill"] = {
            "method": "MANUAL_PUBLIC_SOURCE_REVIEW", "policy": sector_resolution.POLICY_VERSION,
            "evidence_url": review.get("evidence_url", ""),
        }
        fact["Evidence_JSON"] = json.dumps(evidence, ensure_ascii=False, sort_keys=True)
        fact["Source_Metadata_JSON"] = json.dumps(metadata, ensure_ascii=False, sort_keys=True)
        updated.append(item.Item_ID)
    return updated


def _load_json_value(value: str) -> dict:
    try:
        parsed = json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _manual_registry_rows(items: list[Item], decisions: list[dict], as_of: str):
    by_id = {item.Item_ID: item for item in items}
    org_rows, incident_rows = [], []
    for review in decisions:
        left, right = by_id[review["left"]], by_id[review["right"]]
        temporal = dedup._temporal_pair(left, right)
        if temporal is None or abs((temporal[0] - temporal[1]).days) > 14:
            raise ValueError(f"Décision hors borne temporelle : {left.Item_ID}|{right.Item_ID}")
        left_key, right_key = organisation_key(left.Organisation_Raw), organisation_key(right.Organisation_Raw)
        if left_key != right_key:
            org_rows.append({
                "Alias_Key": right_key, "Canonical_Key": left_key,
                "Alias_Raw": right.Organisation_Raw, "Canonical_Raw": left.Organisation_Raw,
                "Decision": "SAME", "Origin": org_identity.ORIGIN_MANUAL,
                "Confidence": str(review["confidence"]), "Evidence": review["evidence"],
                "First_Seen": as_of, "Last_Validated": as_of, "Model": "manual-audit",
                "Prompt_Version": "sector-dedup-audit-2026-09-06", "Input_Hash": "",
            })
        pair = incident_dedup.pair_key(left.Item_ID, right.Item_ID)
        incident_rows.append({
            "Pair_Key": pair, "Left_Item_ID": left.Item_ID, "Right_Item_ID": right.Item_ID,
            "Decision": "SAME", "Confidence": str(review["confidence"]),
            "Evidence": review["evidence"], "Reason": "MANUAL_AUDIT_CONFIRMED",
            "Matched_Facts_JSON": json.dumps(review.get("matched_facts", []), ensure_ascii=False),
            "Conflicting_Facts_JSON": "[]", "First_Seen": as_of, "Last_Validated": as_of,
            "Model": "manual-audit", "Prompt_Version": "sector-dedup-audit-2026-09-06",
            "Input_Hash": "",
        })
    return org_rows, incident_rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=ROOT / "data")
    parser.add_argument("--output-dir", type=Path,
                        default=ROOT / "validation/sector_dedup_2026-09-06/backfill")
    parser.add_argument("--archive", type=Path,
                        default=ROOT / "audit/sector_dedup_2026-09-06/sources")
    parser.add_argument("--decisions", type=Path,
                        default=ROOT / "audit/sector_dedup_2026-09-06/reviewed_dedup_decisions.json")
    parser.add_argument("--sector-decisions", type=Path,
                        default=ROOT / "audit/sector_dedup_2026-09-06/reviewed_sector_decisions.json")
    parser.add_argument("--apply", action="store_true", help="Copier les sorties validées dans data-dir")
    args = parser.parse_args()
    data, out = args.data_dir.resolve(), args.output_dir.resolve()
    items = [Item.from_row(row) for row in store.read_csv(data / "items.csv")]
    old_incidents = [Incident.from_row(row) for row in store.read_csv(data / "incidents.csv")]
    facts = store.read_csv(data / "source_facts.csv")
    cache = _load_json(data / "source_facts_ai_cache.json", {"entries": {}})
    sector_repair.repair_activity_facts(items, facts, cache)
    archive_updated, entity_candidates = _archive_facts(items, facts, args.archive.resolve())
    reviewed_sector_updated = _reviewed_sector_facts(
        items, facts, _load_json(args.sector_decisions.resolve(), [])
    )
    sector_rows = sector_resolution.resolve_items(
        items, facts, enrichment.load_reference(),
        previous_rows=store.read_csv(data / "sector_resolution.csv")
    )
    reviews = _load_json(args.decisions.resolve(), [])
    audit_baseline = _load_json(
        ROOT / "audit/sector_dedup_2026-09-06/local_evidence.json", {}
    ).get("counts", {})
    stamp = "2026-09-06T00:00:00+04:00"
    proposed_org, proposed_incident = _manual_registry_rows(items, reviews, stamp)
    org_rows, org_problems = org_identity.merge_organisation_identity_rows(
        store.read_csv(data / "organisation_identity_registry.csv"), proposed_org
    )
    incident_rows, incident_problems = incident_dedup.merge_rows(
        store.read_csv(data / "incident_dedup_registry.csv"), proposed_incident,
        current_item_ids={item.Item_ID for item in items},
    )
    problems = org_problems + incident_problems
    if problems:
        raise ValueError("; ".join(problems))
    previous_registry = org_identity.ORGANISATION_IDENTITY_REGISTRY
    org_identity.ORGANISATION_IDENTITY_REGISTRY = {
        row["Alias_Key"]: row["Canonical_Key"] for row in org_rows if row.get("Decision") == "SAME"
    }
    try:
        incidents, id_registry = dedup.build_incidents_with_registry(
            items, store.read_csv(data / "incident_id_registry.csv"), incident_rows, facts
        )
    finally:
        org_identity.ORGANISATION_IDENTITY_REGISTRY = previous_registry

    report = {
        "mode": "APPLY" if args.apply else "SEPARATE_OUTPUT",
        "audit_baseline_incidents": audit_baseline.get("incidents"),
        "audit_baseline_unknown": audit_baseline.get("unknown_incidents"),
        "items": len(items), "incidents_before": len(old_incidents), "incidents_after": len(incidents),
        "unknown_before": sum(row.Secteur == config.SECTOR_UNKNOWN for row in old_incidents),
        "unknown_after": sum(row.Secteur == config.SECTOR_UNKNOWN for row in incidents),
        "unknown_incidents_after": [
            {"incident_id": row.Incident_ID, "organisation": row.Organisation}
            for row in incidents if row.Secteur == config.SECTOR_UNKNOWN
        ],
        "sector_archive_items": sorted(archive_updated),
        "sector_reviewed_items": sorted(reviewed_sector_updated),
        "dedup_pairs_applied": [incident_dedup.pair_key(row["left"], row["right"]) for row in reviews],
        "entity_correction_candidates": entity_candidates,
        "api_key_used": False,
    }
    out.mkdir(parents=True, exist_ok=True)
    store.write_csv(out / "items.csv", ITEM_COLUMNS, [item.to_row() for item in items])
    store.write_csv(out / "incidents.csv", INCIDENT_COLUMNS, [incident.to_row() for incident in incidents])
    store.write_csv(out / "source_facts.csv", SOURCE_FACT_COLUMNS, facts)
    store.write_csv(out / "sector_resolution.csv", SECTOR_RESOLUTION_COLUMNS, sector_rows)
    store.write_csv(out / "organisation_identity_registry.csv",
                    org_identity.ORGANISATION_IDENTITY_REGISTRY_COLUMNS, org_rows)
    store.write_csv(out / "incident_dedup_registry.csv", incident_dedup.REGISTRY_COLUMNS, incident_rows)
    store.write_csv(out / "incident_id_registry.csv", store.REGISTRY_COLUMNS, id_registry)
    store.write_csv(out / "dedup_ai_daily_usage.csv", DEDUP_AI_DAILY_USAGE_COLUMNS,
                    store.read_csv(data / "dedup_ai_daily_usage.csv"))
    store.write_json(out / "source_facts_ai_cache.json", cache)
    snapshot = _load_json(data / "snapshot.json", {})
    snapshot.update(
        Items_Count=len(items), Incidents_Count=len(incidents),
        Items_Hash=items_hash(items), Incidents_Hash=incidents_hash(incidents),
    )
    store.write_json(out / "snapshot.json", snapshot)
    store.write_json(out / "backfill_report.json", report)
    if args.apply:
        for path in out.iterdir():
            if path.name != "backfill_report.json":
                shutil.copy2(path, data / path.name)
        shutil.copy2(out / "backfill_report.json", data / "sector_dedup_backfill_report.json")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
