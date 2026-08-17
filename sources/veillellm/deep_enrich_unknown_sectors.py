#!/usr/bin/env python3
"""Enrichit les secteurs challengers depuis des preuves de site officiel.

Cette étape ne classe plus à partir du récit cyber, de snippets de moteurs de
recherche ou d'un annuaire juridique. Les moteurs de recherche servent seulement
à découvrir un site officiel via :mod:`cyberwatch.company_evidence` ; ce module
vérifie ensuite l'identité sur la page officielle et exige une activité forte.

Les URLs d'incident restent dans ``sources``. Les preuves Sector sont persistées
dans des champs dédiés ``sector_evidence_*`` afin que le fallback canonique
puisse les revalider hors ligne sans confondre raccord d'incident et preuve
métier.
"""

from __future__ import annotations

import csv
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import company_evidence, config  # noqa: E402

OUT = ROOT / "sources" / "veillellm"
ITEMS_CSV = ROOT / "data" / "items.csv"

DATASETS = {
    "cyberattaque_org_2026": "CYBERATTAQUE_ORG",
    "frenchbreaches_2026": "FRENCHBREACHES",
}

COLS = [
    "date",
    "organisation",
    "territoire",
    "localisation",
    "secteur",
    "type_menace",
    "acteur",
    "statut",
    "score_cyberattaque",
    "impact_connu",
    "source_urls",
    "synthese",
    "evolution",
    "sector_evidence_url",
    "sector_evidence_text",
    "sector_evidence_source",
    "sector_evidence_type",
]

MAX_WORKERS = 10


def _url_values(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(part).strip() for part in value if str(part).strip()]
    if isinstance(value, str):
        return [part.strip() for part in value.split("|") if part.strip()]
    return []


def incident_urls(row: dict) -> tuple[str, ...]:
    """URLs servant au raccord incident, jamais comme preuve Sector."""
    values = row.get("sources") or row.get("source_urls") or []
    return tuple(dict.fromkeys(_url_values(values)))


def target_unknown_urls(source_id: str, path: Path = ITEMS_CSV) -> set[str]:
    """URLs des items production encore sans secteur pour cette source."""
    if not path.exists():
        return set()
    targets: set[str] = set()
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("Source_ID") != source_id:
                continue
            if row.get("Sector") != config.SECTOR_UNKNOWN:
                continue
            url = str(row.get("URL") or "").strip()
            if url:
                targets.add(url)
    return targets


def is_target_row(row: dict, target_urls: set[str]) -> bool:
    return bool(target_urls.intersection(incident_urls(row)))


def apply_evidence(
    row: dict,
    evidence: company_evidence.CompanyEvidence,
) -> tuple[str, str]:
    """Persiste une preuve officielle séparée et retourne (avant, après)."""
    before = str(row.get("secteur") or config.SECTOR_UNKNOWN)
    row["secteur"] = evidence.sector
    row["sector_evidence_url"] = evidence.evidence_url
    row["sector_evidence_text"] = evidence.evidence_text
    row["sector_evidence_source"] = evidence.evidence_source
    row["sector_evidence_type"] = evidence.evidence_type
    if before != evidence.sector and row.get("evolution") != "nouveau":
        row["evolution"] = "enrichi"
    return before, evidence.sector


def research_official_evidence(row: dict) -> company_evidence.CompanyEvidence | None:
    organisation = str(row.get("organisation") or "").strip()
    if not organisation:
        return None
    return company_evidence.resolve_official_site(organisation)


def write_csv(path: Path, incidents: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLS, extrasaction="ignore")
        writer.writeheader()
        for row in incidents:
            output = {column: row.get(column, "") for column in COLS}
            output["source_urls"] = " | ".join(incident_urls(row))
            writer.writerow(output)


def run(stem: str, source_id: str) -> dict[str, int]:
    json_path = OUT / f"{stem}.json"
    csv_path = OUT / f"{stem}.csv"
    data = json.loads(json_path.read_text(encoding="utf-8"))
    incidents = data.get("incidents") or []
    if not isinstance(incidents, list):
        raise ValueError(f"{json_path}: incidents doit être une liste")

    target_urls = target_unknown_urls(source_id)
    targets = [
        (index, row)
        for index, row in enumerate(incidents)
        if isinstance(row, dict) and is_target_row(row, target_urls)
    ]

    stats = {
        "target_items": len(target_urls),
        "target_records": len(targets),
        "evidence_found": 0,
        "resolved_unknown": 0,
        "corrected_known": 0,
        "verified_same": 0,
        "no_official_evidence": 0,
    }

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(research_official_evidence, row): index
            for index, row in targets
        }
        for future in as_completed(futures):
            index = futures[future]
            try:
                evidence = future.result()
            except Exception:
                evidence = None
            if evidence is None:
                stats["no_official_evidence"] += 1
                continue

            before, after = apply_evidence(incidents[index], evidence)
            stats["evidence_found"] += 1
            if before == config.SECTOR_UNKNOWN and after != config.SECTOR_UNKNOWN:
                stats["resolved_unknown"] += 1
            elif before != after:
                stats["corrected_known"] += 1
            else:
                stats["verified_same"] += 1

    metadata = data.setdefault("metadata", {})
    metadata["sector_evidence_v2"] = {
        **stats,
        "method": "official-site discovery + exact identity/activity validation via cyberwatch.company_evidence",
        "evidence_policy": (
            "search engines are discovery-only; incident text, search snippets, legal directories "
            "and source article URLs are never Sector evidence"
        ),
    }

    json_path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    write_csv(csv_path, incidents)

    print(
        stem,
        "TARGET_RECORDS", stats["target_records"],
        "EVIDENCE", stats["evidence_found"],
        "RESOLVED", stats["resolved_unknown"],
        "CORRECTED", stats["corrected_known"],
        "VERIFIED", stats["verified_same"],
        "NO_EVIDENCE", stats["no_official_evidence"],
        flush=True,
    )
    return stats


def main() -> None:
    for stem, source_id in DATASETS.items():
        run(stem, source_id)


if __name__ == "__main__":
    main()
