"""Observation incrémentale au niveau organisation.

Cette couche mesure les organisations réellement modifiées. Elle ne court-
circuite pas encore le registre Sector : le skip organisationnel ne doit être
activé que lorsqu'une parité dédiée aura démontré qu'il est indépendant du
reste du corpus.
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Mapping

from .model import Item

ORG_FINGERPRINT_VERSION = "ORG-FP-1"
ORG_STATE_COLUMNS = [
    "Organisation_Key", "Organisation_Fingerprint", "Policy_Version",
    "Last_Run_ID", "Last_As_Of",
]
ORG_METRIC_COLUMNS = [
    "Run_ID", "As_Of", "Mode", "Organisations_Count", "New_Organisations",
    "Dirty_Organisations", "Unchanged_Organisations", "Org_Reuse_Rate",
]


def _hash(payload: object) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _stable_rows(rows: Iterable[Mapping[str, object]], ignored=()) -> list[dict[str, str]]:
    ignored = set(ignored)
    values = [
        {str(k): str(v or "") for k, v in sorted(row.items()) if str(k) not in ignored}
        for row in rows
    ]
    return sorted(values, key=lambda row: json.dumps(row, ensure_ascii=False, sort_keys=True))


def fingerprints(
    items: Iterable[Item],
    source_facts: Iterable[Mapping[str, object]],
    reference_rows: Iterable[Mapping[str, object]],
    org_cache_rows: Iterable[Mapping[str, object]],
    *,
    policy_version: str,
    code_paths: Iterable[Path] = (),
) -> dict[str, str]:
    items_by_org = defaultdict(list)
    item_to_org = {}
    for item in items:
        key = item.Organisation_Key or ""
        if not key:
            continue
        items_by_org[key].append(item)
        item_to_org[item.Item_ID] = key

    facts_by_org = defaultdict(list)
    for row in source_facts:
        key = item_to_org.get(str(row.get("Item_ID") or ""))
        if key:
            facts_by_org[key].append(row)

    refs_by_org = defaultdict(list)
    for row in reference_rows:
        key = str(row.get("Organisation_Key") or row.get("Organisation") or "")
        if key:
            refs_by_org[key].append(row)

    cache_by_org = defaultdict(list)
    for row in org_cache_rows:
        key = str(row.get("Organisation_Key") or "")
        if key:
            cache_by_org[key].append(row)

    code = []
    for path in sorted((Path(p) for p in code_paths), key=lambda p: str(p)):
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            digest = ""
        code.append((path.name, digest))

    result = {}
    for key, org_items in sorted(items_by_org.items()):
        item_rows = []
        for item in sorted(org_items, key=lambda value: value.Item_ID):
            item_rows.append({
                "Item_ID": item.Item_ID,
                "Source_ID": item.Source_ID,
                "Source_Item_ID": item.Source_Item_ID,
                "Published_Date": item.Published_Date,
                "Event_Date": item.Event_Date,
                "Organisation_Raw": item.Organisation_Raw,
                "Organisation_Key": item.Organisation_Key,
                "Threat_Raw": item.Threat_Raw,
                "Title": item.Title,
                "URL": item.URL,
            })
        result[key] = _hash({
            "version": ORG_FINGERPRINT_VERSION,
            "policy": policy_version,
            "items": item_rows,
            "source_facts": _stable_rows(facts_by_org.get(key, ()), ignored={"Collected_As_Of"}),
            "reference": _stable_rows(refs_by_org.get(key, ())),
            "org_cache": _stable_rows(cache_by_org.get(key, ())),
            "code": code,
        })
    return result


def previous_fingerprints(rows: Iterable[Mapping[str, object]]) -> dict[str, str]:
    return {
        str(row.get("Organisation_Key") or ""): str(row.get("Organisation_Fingerprint") or "")
        for row in rows
        if row.get("Organisation_Key") and row.get("Organisation_Fingerprint")
    }


def classify(current: Mapping[str, str], previous: Mapping[str, str]):
    new, dirty, unchanged = [], [], []
    for key, fingerprint in sorted(current.items()):
        old = previous.get(key)
        (new if old is None else unchanged if old == fingerprint else dirty).append(key)
    return tuple(new), tuple(dirty), tuple(unchanged)


def state_rows(current: Mapping[str, str], *, policy_version: str, run_id: str, as_of: str):
    return [
        {
            "Organisation_Key": key,
            "Organisation_Fingerprint": fingerprint,
            "Policy_Version": policy_version,
            "Last_Run_ID": run_id,
            "Last_As_Of": as_of,
        }
        for key, fingerprint in sorted(current.items())
    ]


def metric_row(current: Mapping[str, str], previous: Mapping[str, str], *, run_id: str, as_of: str, mode: str):
    new, dirty, unchanged = classify(current, previous)
    total = len(current)
    return {
        "Run_ID": run_id,
        "As_Of": as_of,
        "Mode": mode,
        "Organisations_Count": str(total),
        "New_Organisations": str(len(new)),
        "Dirty_Organisations": str(len(dirty)),
        "Unchanged_Organisations": str(len(unchanged)),
        "Org_Reuse_Rate": f"{(len(unchanged) / total) if total else 1.0:.6f}",
    }
