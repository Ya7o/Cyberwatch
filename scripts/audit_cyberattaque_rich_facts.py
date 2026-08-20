#!/usr/bin/env python3
"""Audit reproductible de la qualité des rich facts Cyberattaque.org."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from cyberwatch import store
from cyberwatch.normalize import searchable

SOURCE_ID = "CYBERATTAQUE_ORG"
VALID_STATUSES = {"confirmed", "reported", "claimed", "hypothesis", "denied", "negated", "unknown"}
COLLECTIONS = ("affected_counts", "data_volumes", "data_types", "affected_systems", "affected_datasets", "timeline", "relations", "vulnerabilities")
HYPOTHETICAL_RE = re.compile(r"\b(?:pourrait|pourraient|potentiellement|possible|hypoth[èe]se|susceptible|non\s+confirm[ée]|sans\s+confirmation|serait|auraient?|présum[ée])\b", re.I)
NUMBER_RE = re.compile(r"\d[\d\s\u202f.,]*")


def _rich(row: dict) -> dict | None:
    try:
        metadata = json.loads(row.get("Source_Metadata_JSON") or "{}")
    except (TypeError, ValueError):
        return None
    rich = metadata.get("rich_facts") if isinstance(metadata, dict) else None
    return rich if isinstance(rich, dict) else None


def _evidence(record: dict) -> str:
    return str(record.get("evidence") or "").strip()


def _numeric_supported(record: dict) -> bool:
    value = record.get("value")
    if not isinstance(value, (int, float)):
        return True
    evidence = _evidence(record)
    if not evidence:
        return False
    compact = searchable(evidence).replace(" ", "")
    raw_value = str(value).rstrip("0").rstrip(".") if isinstance(value, float) else str(value)
    if raw_value.replace(".", "") in re.sub(r"\D", "", compact):
        return True
    for raw in NUMBER_RE.findall(evidence):
        token = raw.replace("\u202f", "").replace(" ", "").replace(",", ".")
        try:
            number = float(token)
        except ValueError:
            continue
        low = searchable(evidence)
        if "million" in low and abs(number * 1_000_000 - float(value)) < 1:
            return True
        if ("millier" in low or "mille" in low) and abs(number * 1_000 - float(value)) < 1:
            return True
        if abs(number - float(value)) < 1e-9:
            return True
    return False


def _records(rich: dict):
    for key in COLLECTIONS + ("claims",):
        values = rich.get(key) or []
        if isinstance(values, list):
            for value in values:
                if isinstance(value, dict):
                    yield key, value


def audit_rows(rows: list[dict]) -> dict:
    coverage, statuses, types, errors, profiles = Counter(), Counter(), Counter(), Counter(), Counter()
    total_claims = total_records = evidence_records = 0
    for row in rows:
        rich = _rich(row)
        if not rich:
            coverage["without_rich_facts"] += 1
            continue
        coverage["with_rich_facts"] += 1
        if str(rich.get("version") or "") == "2":
            coverage["with_schema_v2"] += 1
        dimensions = 0
        for key in COLLECTIONS:
            values = rich.get(key) or []
            if isinstance(values, list) and values:
                coverage[f"articles_with_{key}"] += 1
                dimensions += 1
        if dimensions >= 3:
            coverage["articles_rich_3plus_dimensions"] += 1
        claims = rich.get("claims") or []
        if not isinstance(claims, list):
            claims = []
        total_claims += len(claims)
        if len(claims) > 1:
            coverage["articles_multi_claims"] += 1
        profile = rich.get("profile") or {}
        if isinstance(profile, dict):
            for key, value in profile.items():
                if value is True:
                    profiles[str(key)] += 1
        seen = set()
        has_hypothesis = False
        for collection, record in _records(rich):
            total_records += 1
            evidence = _evidence(record)
            if evidence:
                evidence_records += 1
            else:
                errors["records_without_evidence"] += 1
            status = str(record.get("status") or "unknown").strip().lower()
            statuses[status] += 1
            if status not in VALID_STATUSES:
                errors["invalid_status"] += 1
            if status == "hypothesis":
                has_hypothesis = True
            if status == "confirmed" and evidence and HYPOTHETICAL_RE.search(evidence):
                errors["confirmed_with_hypothetical_evidence"] += 1
            if not _numeric_supported(record):
                errors["numeric_value_not_in_evidence"] += 1
            sig = (collection, searchable(str(record.get("type") or record.get("kind") or "")), searchable(str(record.get("value") or "")), searchable(str(record.get("unit") or "")), searchable(str(record.get("scope") or "")), status, searchable(evidence))
            if sig in seen:
                errors["duplicate_records"] += 1
            seen.add(sig)
            if collection == "claims":
                types[str(record.get("type") or record.get("kind") or "statement")] += 1
        if has_hypothesis:
            coverage["articles_with_hypotheses"] += 1
    articles = len(rows)
    return {
        "source": SOURCE_ID,
        "articles": articles,
        "total_claims": total_claims,
        "total_records": total_records,
        "evidence_records": evidence_records,
        "metrics": {
            "rich_coverage": round(coverage["with_rich_facts"] / articles, 4) if articles else 0.0,
            "schema_v2_coverage": round(coverage["with_schema_v2"] / articles, 4) if articles else 0.0,
            "evidence_coverage": round(evidence_records / total_records, 4) if total_records else 1.0,
            "error_rate": round(sum(errors.values()) / total_records, 4) if total_records else 0.0,
        },
        "coverage": dict(sorted(coverage.items())),
        "claim_statuses": dict(sorted(statuses.items())),
        "claim_types": dict(sorted(types.items())),
        "article_profiles": dict(sorted(profiles.items())),
        "quality_errors": dict(sorted(errors.items())),
    }


def _stratum(row: dict) -> str:
    rich = _rich(row) or {}
    claims = rich.get("claims") or []
    statuses = {str(c.get("status") or "unknown") for c in claims if isinstance(c, dict)}
    if statuses & {"hypothesis", "negated", "denied"}: return "modalite"
    if len(rich.get("timeline") or []) >= 2: return "chronologie"
    if rich.get("relations"): return "relations"
    if len(rich.get("affected_counts") or []) >= 2 or len(rich.get("data_volumes") or []) >= 2: return "multi_chiffres"
    if len(claims) >= 3: return "riche"
    return "simple"


def review_sample(rows: list[dict], limit: int = 100) -> list[dict]:
    buckets = defaultdict(list)
    for row in rows:
        buckets[_stratum(row)].append(row)
    for values in buckets.values():
        values.sort(key=lambda r: hashlib.sha256(str(r.get("Item_ID") or r.get("URL") or "").encode()).hexdigest())
    out, strata = [], sorted(buckets)
    while len(out) < limit and any(buckets.values()):
        progressed = False
        for stratum in strata:
            if len(out) >= limit: break
            if not buckets[stratum]: continue
            row = buckets[stratum].pop(0); rich = _rich(row) or {}; claims = rich.get("claims") or []
            out.append({"Item_ID": row.get("Item_ID", ""), "URL": row.get("URL", ""), "Organisation_Raw": row.get("Organisation_Raw", ""), "stratum": stratum, "claim_count": len(claims), "status_set": ",".join(sorted({str(c.get("status") or "unknown") for c in claims if isinstance(c, dict)})), "review_precision_ok": "", "review_notes": ""})
            progressed = True
        if not progressed: break
    return out


def write_review_sample(path: Path, sample: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["Item_ID", "URL", "Organisation_Raw", "stratum", "claim_count", "status_set", "review_precision_ok", "review_notes"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields); writer.writeheader(); writer.writerows(sample)


def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("--output", default=""); parser.add_argument("--review-sample", default=""); parser.add_argument("--review-limit", type=int, default=100); args = parser.parse_args()
    rows = [r for r in store.load_source_facts() if r.get("Source_ID") == SOURCE_ID]
    payload = audit_rows(rows); text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        path = Path(args.output); path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text + "\n", encoding="utf-8")
    if args.review_sample: write_review_sample(Path(args.review_sample), review_sample(rows, args.review_limit))
    print(text)


if __name__ == "__main__": main()
