"""Fallback conservateur depuis les exports LLM versionnés par source.

Ces exports sont des challengers analytiques, pas une nouvelle vérité globale :
- Localisation peut compléter uniquement ``Inconnu`` pour FrenchBreaches et
  Cyberattaque.org ;
- Secteur peut compléter ``Inconnu`` seulement avec raccord par URL exacte et
  une preuve externe conservée dans l'export ;
- Menace n'est jamais modifiée par cette couche.

Toute décision appliquée ou explicitement refusée est rendue sous forme de
provenance afin de rester auditée sans modifier l'identité canonique des items.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from . import config
from .model import Item
from .normalize import organisation_key, searchable

ROOT = Path(__file__).resolve().parents[1]

SOURCE_FILES = {
    "FRENCHBREACHES": ROOT / "sources" / "veillellm" / "frenchbreaches_2026.json",
    "CYBERATTAQUE_ORG": ROOT / "sources" / "veillellm" / "cyberattaque_org_2026.json",
}

SOURCE_HOSTS = {
    "FRENCHBREACHES": {"frenchbreaches.com", "www.frenchbreaches.com"},
    "CYBERATTAQUE_ORG": {"cyberattaque.org", "www.cyberattaque.org"},
}

DISCOVERY_HOSTS = {
    "bing.com", "www.bing.com",
    "duckduckgo.com", "www.duckduckgo.com",
    "google.com", "www.google.com",
}

QUALIFICATION_PROVENANCE_COLUMNS = [
    "Item_ID",
    "Source_ID",
    "Field",
    "Previous_Value",
    "Candidate_Value",
    "Final_Value",
    "Origin",
    "Confidence",
    "Evidence",
    "Match_Strategy",
    "Decision",
]


@dataclass(frozen=True)
class ChallengerRecord:
    source_id: str
    date: str
    organisation: str
    organisation_key: str
    urls: tuple[str, ...]
    sector: str
    location: str
    threat: str
    raw_location: str
    evidence_urls: tuple[str, ...]


def _clean_url(value: object) -> str:
    return str(value or "").strip()


def _record_urls(raw: dict) -> tuple[str, ...]:
    values = raw.get("sources") or raw.get("source_urls") or raw.get("Source_URLs") or []
    if isinstance(values, str):
        values = [part.strip() for part in values.split("|")]
    if not isinstance(values, list):
        return ()
    return tuple(dict.fromkeys(_clean_url(value) for value in values if _clean_url(value)))


def canonical_location(value: object) -> str:
    raw = searchable(str(value or ""))
    if not raw or raw == searchable(config.LOC_INCONNU):
        return config.LOC_INCONNU
    if "reunion" in raw or raw == "974":
        return config.LOC_REUNION
    if "mayotte" in raw or raw == "976":
        return config.LOC_MAYOTTE
    if "maurice" in raw or "mauritius" in raw:
        return config.LOC_MAURICE
    if "madagascar" in raw:
        return config.LOC_MADAGASCAR
    if "seychelles" in raw:
        return config.LOC_SEYCHELLES
    if "comores" in raw or "comoros" in raw:
        return config.LOC_COMORES
    if (
        "france" in raw
        or "paris" in raw
        or "ile de france" in raw
        or raw in {"idf", "metropole", "metropolitaine"}
    ):
        return config.LOC_FRANCE
    return config.LOC_INCONNU


def canonical_sector(value: object) -> str:
    cleaned = str(value or "").strip()
    return cleaned if cleaned in config.SECTORS else config.SECTOR_UNKNOWN


def canonical_threat(value: object) -> str:
    cleaned = str(value or "").strip()
    return cleaned if cleaned in config.THREATS else config.THREAT_UNKNOWN


def _external_evidence(source_id: str, urls: tuple[str, ...]) -> tuple[str, ...]:
    rejected = SOURCE_HOSTS.get(source_id, set()) | DISCOVERY_HOSTS
    kept: list[str] = []
    for url in urls:
        try:
            host = (urlparse(url).hostname or "").lower()
        except ValueError:
            continue
        if not host or host in rejected:
            continue
        kept.append(url)
    return tuple(dict.fromkeys(kept))


def load_records(path: Path, source_id: str) -> list[ChallengerRecord]:
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    if isinstance(payload, dict):
        rows = payload.get("incidents") or payload.get("records") or payload.get("items") or []
    else:
        rows = payload
    if not isinstance(rows, list):
        return []

    records: list[ChallengerRecord] = []
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        organisation = str(raw.get("organisation") or raw.get("Organisation") or "").strip()
        raw_location = str(
            raw.get("territoire")
            or raw.get("localisation")
            or raw.get("Localisation")
            or ""
        ).strip()
        urls = _record_urls(raw)
        records.append(
            ChallengerRecord(
                source_id=source_id,
                date=str(raw.get("date") or raw.get("Date") or "").strip()[:10],
                organisation=organisation,
                organisation_key=organisation_key(organisation),
                urls=urls,
                sector=canonical_sector(raw.get("secteur") or raw.get("Secteur")),
                location=canonical_location(raw_location),
                threat=canonical_threat(raw.get("type_menace") or raw.get("Menace")),
                raw_location=raw_location,
                evidence_urls=_external_evidence(source_id, urls),
            )
        )
    return records


@lru_cache(maxsize=1)
def load_all() -> dict[str, list[ChallengerRecord]]:
    return {
        source_id: load_records(path, source_id)
        for source_id, path in SOURCE_FILES.items()
    }


def _date_distance(left: str, right: str) -> int | None:
    if not left or not right:
        return None
    try:
        return abs((date.fromisoformat(left[:10]) - date.fromisoformat(right[:10])).days)
    except ValueError:
        return None


def match_record(
    item: Item,
    records: list[ChallengerRecord],
) -> tuple[ChallengerRecord | None, str]:
    """Raccorde sans similarité floue et refuse toute ambiguïté."""
    if item.URL:
        exact = [record for record in records if item.URL in record.urls]
        if len(exact) == 1:
            return exact[0], "source_url"
        if len(exact) > 1:
            return None, "ambiguous_source_url"

    key = item.Organisation_Key or organisation_key(item.Organisation_Raw)
    if not key:
        return None, "no_match"
    candidates = []
    for record in records:
        if record.organisation_key != key:
            continue
        distance = _date_distance(item.best_date, record.date)
        if distance is not None and distance <= 3:
            candidates.append(record)
    if len(candidates) == 1:
        return candidates[0], "organisation_date"
    if len(candidates) > 1:
        return None, "ambiguous_organisation_date"
    return None, "no_match"


def _provenance_row(
    item: Item,
    field: str,
    previous: str,
    candidate: str,
    final: str,
    *,
    confidence: str,
    evidence: str,
    strategy: str,
    decision: str,
) -> dict[str, str]:
    return {
        "Item_ID": item.Item_ID,
        "Source_ID": item.Source_ID,
        "Field": field,
        "Previous_Value": previous,
        "Candidate_Value": candidate,
        "Final_Value": final,
        "Origin": "LLM_SOURCE_FALLBACK",
        "Confidence": confidence,
        "Evidence": evidence,
        "Match_Strategy": strategy,
        "Decision": decision,
    }


def apply_source_llm_fallback(
    items: list[Item],
    records_by_source: dict[str, list[ChallengerRecord]] | None = None,
) -> tuple[dict[str, int], list[dict[str, str]]]:
    """Complète uniquement les inconnues autorisées et retourne leur provenance."""
    records_by_source = load_all() if records_by_source is None else records_by_source
    stats = {
        "llm_location_fallback": 0,
        "llm_sector_fallback": 0,
        "llm_sector_rejected": 0,
        "llm_threat_protected": 0,
        "llm_match_ambiguous": 0,
    }
    provenance: list[dict[str, str]] = []

    for item in items:
        records = records_by_source.get(item.Source_ID)
        if not records:
            continue
        record, strategy = match_record(item, records)
        if record is None:
            if strategy.startswith("ambiguous"):
                stats["llm_match_ambiguous"] += 1
            continue

        # Menace : le challenger reste strictement diagnostique.
        if record.threat != config.THREAT_UNKNOWN:
            stats["llm_threat_protected"] += 1
            provenance.append(
                _provenance_row(
                    item,
                    "Threat",
                    item.Threat,
                    record.threat,
                    item.Threat,
                    confidence="",
                    evidence="challenger diagnostic only; canonical Threat protected",
                    strategy=strategy,
                    decision="PROTECTED",
                )
            )

        # Localisation : fallback uniquement, sans écraser une vérité connue.
        if item.Location == config.LOC_INCONNU and record.location != config.LOC_INCONNU:
            previous = item.Location
            item.Location = record.location
            stats["llm_location_fallback"] += 1
            provenance.append(
                _provenance_row(
                    item,
                    "Location",
                    previous,
                    record.location,
                    item.Location,
                    confidence="HIGH" if strategy == "source_url" else "MEDIUM",
                    evidence=record.raw_location or record.location,
                    strategy=strategy,
                    decision="APPLIED",
                )
            )

        # Secteur : exact URL + preuve externe obligatoire.
        if item.Sector == config.SECTOR_UNKNOWN and record.sector != config.SECTOR_UNKNOWN:
            if strategy == "source_url" and record.evidence_urls:
                previous = item.Sector
                item.Sector = record.sector
                stats["llm_sector_fallback"] += 1
                provenance.append(
                    _provenance_row(
                        item,
                        "Sector",
                        previous,
                        record.sector,
                        item.Sector,
                        confidence="HIGH",
                        evidence=" | ".join(record.evidence_urls),
                        strategy=strategy,
                        decision="APPLIED",
                    )
                )
            else:
                stats["llm_sector_rejected"] += 1
                provenance.append(
                    _provenance_row(
                        item,
                        "Sector",
                        item.Sector,
                        record.sector,
                        item.Sector,
                        confidence="",
                        evidence=" | ".join(record.evidence_urls),
                        strategy=strategy,
                        decision="REJECTED_NO_STRONG_EVIDENCE",
                    )
                )

    provenance.sort(key=lambda row: (row["Item_ID"], row["Field"], row["Decision"]))
    return stats, provenance
