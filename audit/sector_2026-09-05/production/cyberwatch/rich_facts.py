"""Generic evidence-first rich-facts utilities for editorial sources.

The module is intentionally source-agnostic: collectors provide article text and
source-specific cleanup only. Facts are represented as atomic claims with explicit
status, scope, provenance and evidence. Summary fields remain projections of those
claims for backward compatibility.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Iterable

VALID_STATUSES = {
    "confirmed", "reported", "claimed", "hypothesis", "denied", "negated", "unknown"
}
STATUS_PRIORITY = {
    "confirmed": 6,
    "reported": 5,
    "claimed": 4,
    "hypothesis": 3,
    "denied": 2,
    "negated": 2,
    "unknown": 1,
}

@dataclass(frozen=True)
class RichClaim:
    type: str
    status: str = "unknown"
    value: object = ""
    unit: str = ""
    scope: str = ""
    date: str = ""
    actor: str = ""
    subject: str = ""
    evidence: str = ""
    source_position: int | None = None
    source_id: str = ""
    item_id: str = ""

    def as_dict(self) -> dict:
        data = {"type": self.type, "status": normalize_status(self.status)}
        for key in ("value", "unit", "scope", "date", "actor", "subject", "evidence", "source_id", "item_id"):
            value = getattr(self, key)
            if value not in (None, "", [], {}):
                data[key] = value
        if self.source_position is not None:
            data["source_position"] = self.source_position
        return data


def normalize_status(value: object) -> str:
    status = str(value or "unknown").strip().lower()
    return status if status in VALID_STATUSES else "unknown"


def evidence_in_text(evidence: str, text: str) -> bool:
    if not evidence or not text:
        return False
    compact = lambda s: re.sub(r"\s+", " ", s).strip()
    return compact(evidence) in compact(text)


def numbers_in(value: object) -> set[str]:
    return set(re.findall(r"\d+(?:[.,]\d+)?", str(value or "")))


def validate_claim(claim: dict, text: str) -> dict | None:
    if not isinstance(claim, dict):
        return None
    evidence = str(claim.get("evidence") or "").strip()
    if not evidence_in_text(evidence, text):
        return None
    result = dict(claim)
    result["status"] = normalize_status(result.get("status"))
    value_numbers = numbers_in(result.get("value"))
    if value_numbers and not value_numbers.issubset(numbers_in(evidence)):
        return None
    result["evidence"] = evidence[:500]
    return result


def claim_key(claim: dict) -> tuple:
    return (
        str(claim.get("type") or claim.get("kind") or "statement"),
        normalize_status(claim.get("status")),
        json.dumps(claim.get("value", ""), ensure_ascii=False, sort_keys=True, default=str),
        str(claim.get("unit") or ""),
        str(claim.get("scope") or ""),
        str(claim.get("date") or ""),
        re.sub(r"\s+", " ", str(claim.get("evidence") or "")).strip(),
    )


def dedupe_claims(claims: Iterable[dict]) -> list[dict]:
    out, seen = [], set()
    for claim in claims:
        key = claim_key(claim)
        if key in seen:
            continue
        seen.add(key)
        out.append(claim)
    return out


def merge_claims(*collections: Iterable[dict]) -> list[dict]:
    return dedupe_claims(claim for collection in collections for claim in collection)


def primary_claim(claims: Iterable[dict], claim_type: str) -> dict | None:
    candidates = [c for c in claims if str(c.get("type") or c.get("kind")) == claim_type]
    if not candidates:
        return None
    return sorted(
        candidates,
        key=lambda c: (
            -STATUS_PRIORITY.get(normalize_status(c.get("status")), 0),
            str(c.get("date") or ""),
            str(c.get("evidence") or ""),
        ),
    )[0]


def content_hash(text: str, *, source_id: str = "", version: str = "") -> str:
    payload = f"{source_id}\0{version}\0{text}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def enrich_provenance(rich: dict, *, source_id: str, item_id: str) -> dict:
    result = dict(rich or {})
    for key, values in list(result.items()):
        if not isinstance(values, list):
            continue
        enriched = []
        for value in values:
            if not isinstance(value, dict):
                enriched.append(value)
                continue
            row = dict(value)
            row.setdefault("source_id", source_id)
            row.setdefault("item_id", item_id)
            enriched.append(row)
        result[key] = enriched
    return result


def fact_history(claims: Iterable[dict]) -> list[dict]:
    """Return stable chronological knowledge history without collapsing divergence."""
    rows = dedupe_claims(claims)
    rows.sort(key=lambda c: (str(c.get("date") or "9999-99-99"), -STATUS_PRIORITY.get(normalize_status(c.get("status")), 0), str(c.get("evidence") or "")))
    return rows


def divergence_groups(claims: Iterable[dict]) -> list[dict]:
    """Group materially different values for the same type/scope across sources."""
    groups: dict[tuple[str, str], list[dict]] = {}
    for claim in claims:
        ctype = str(claim.get("type") or claim.get("kind") or "statement")
        scope = str(claim.get("scope") or "")
        groups.setdefault((ctype, scope), []).append(claim)
    out = []
    for (ctype, scope), rows in groups.items():
        values = {json.dumps(r.get("value", ""), ensure_ascii=False, sort_keys=True, default=str) for r in rows}
        if len(values) < 2:
            continue
        out.append({"type": ctype, "scope": scope, "claims": dedupe_claims(rows)})
    return out
