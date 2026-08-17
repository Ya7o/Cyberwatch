#!/usr/bin/env python3
"""Enrichit les secteurs challengers depuis des preuves de site officiel.

Cette étape ne classe jamais à partir du récit cyber, d'un snippet de moteur de
recherche ou d'un annuaire juridique. La découverte est déterministe : domaines
explicitement cités ou dérivés du nom de l'organisation. Chaque URL candidate
est ensuite téléchargée et doit passer les contrôles d'identité et d'activité de
:mod:`cyberwatch.company_evidence` avant de devenir une preuve Sector.

Une seconde barrière est volontairement plus stricte : le texte conservé comme
preuve doit contenir une formulation explicite d'activité métier reconnue par
``extract_activity_description`` (par exemple ``fournisseur de``, ``éditeur de``
ou ``spécialisé dans``). Un mot isolé dans une page officielle — « crédit »,
« logistique », « construction » — ne suffit donc jamais.

Les URLs d'incident restent dans ``sources``. Les preuves Sector sont persistées
dans des champs dédiés ``sector_evidence_*`` afin que le fallback canonique
puisse les revalider hors ligne sans confondre raccord d'incident et preuve
métier.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import company_evidence, config  # noqa: E402
from cyberwatch.normalize import (  # noqa: E402
    classify_sector,
    extract_activity_description,
    searchable,
)

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

SECTOR_EVIDENCE_FIELDS = (
    "sector_evidence_url",
    "sector_evidence_text",
    "sector_evidence_source",
    "sector_evidence_type",
)

MAX_WORKERS = 12
MAX_DOMAIN_CANDIDATES = 6

_DOMAIN_RE = re.compile(
    r"(?<!@)\b(?:https?://)?(?:www\.)?"
    r"((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"(?:fr|com|org|net|io|gg|re|yt))\b",
    re.I,
)
_LEGAL_SUFFIXES = {
    "sas", "sasu", "sa", "sarl", "eurl", "ltd", "limited", "inc", "corp",
    "corporation", "company", "co", "groupe", "group", "holding",
}


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


def has_sector_evidence(row: dict) -> bool:
    return any(str(row.get(field) or "").strip() for field in SECTOR_EVIDENCE_FIELDS)


def is_target_row(row: dict, target_urls: set[str]) -> bool:
    """Reprend aussi toute preuve v3 afin de réauditer les valeurs déjà injectées."""
    return bool(target_urls.intersection(incident_urls(row))) or has_sector_evidence(row)


def clear_sector_evidence(row: dict) -> None:
    """Retire une ancienne preuve devenue insuffisante et neutralise son label."""
    for field in SECTOR_EVIDENCE_FIELDS:
        row.pop(field, None)
    row["secteur"] = config.SECTOR_UNKNOWN


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
    row["sector_evidence_type"] = "official_explicit_activity"
    if before != evidence.sector and row.get("evolution") != "nouveau":
        row["evolution"] = "enrichi"
    return before, evidence.sector


def strict_activity_evidence(
    evidence: company_evidence.CompanyEvidence,
) -> company_evidence.CompanyEvidence | None:
    """Exige une phrase métier explicite puis recalcule le secteur localement."""
    activity = extract_activity_description(evidence.evidence_text)
    if not activity:
        return None
    sector = classify_sector(activity)
    if sector == config.SECTOR_UNKNOWN:
        return None
    return company_evidence.CompanyEvidence(
        sector=sector,
        evidence_url=evidence.evidence_url,
        evidence_text=activity,
        evidence_source=evidence.evidence_source,
        evidence_type="official_explicit_activity",
    )


def strict_existing_evidence(row: dict) -> company_evidence.CompanyEvidence | None:
    """Réévalue hors ligne les preuves v3 déjà présentes avant tout nouvel HTTP."""
    url = str(row.get("sector_evidence_url") or "").strip()
    text = str(row.get("sector_evidence_text") or "").strip()
    if not url or not text or company_evidence._blocked(url):
        return None
    evidence = company_evidence.CompanyEvidence(
        sector=str(row.get("secteur") or config.SECTOR_UNKNOWN),
        evidence_url=url,
        evidence_text=text,
        evidence_source=str(row.get("sector_evidence_source") or "official_site"),
        evidence_type=str(row.get("sector_evidence_type") or "official_site"),
    )
    return strict_activity_evidence(evidence)


def _domain_guess_tokens(organisation: str) -> list[str]:
    tokens = [
        token
        for token in searchable(organisation).split()
        if len(token) > 1 and token not in _LEGAL_SUFFIXES
    ]
    return tokens[:6]


def candidate_official_urls(row: dict) -> tuple[str, ...]:
    """Produit des pistes déterministes ; aucune n'est encore une preuve."""
    values: list[str] = []
    discovery_text = " ".join(
        str(row.get(field) or "")
        for field in ("organisation", "impact_connu", "synthese")
    )
    for match in _DOMAIN_RE.finditer(discovery_text):
        values.append("https://" + match.group(1).lower())

    organisation = str(row.get("organisation") or "").strip()
    tokens = _domain_guess_tokens(organisation)
    if tokens:
        slugs = []
        hyphenated = "-".join(tokens)
        compact = "".join(tokens)
        for slug in (hyphenated, compact):
            if slug and slug not in slugs:
                slugs.append(slug)
        for slug in slugs:
            for tld in ("fr", "com", "org"):
                values.append(f"https://{slug}.{tld}")

    kept: list[str] = []
    for url in values:
        if url in kept or company_evidence._blocked(url):
            continue
        kept.append(url)
        if len(kept) >= MAX_DOMAIN_CANDIDATES:
            break
    return tuple(kept)


def _domain_matches_organisation(organisation: str, url: str) -> bool:
    tokens = company_evidence._org_tokens(organisation)
    if not tokens:
        return False
    domain = searchable(company_evidence._domain(url))
    return any(token in domain for token in tokens)


def validate_official_candidate(
    organisation: str,
    candidate: str,
) -> company_evidence.CompanyEvidence | None:
    """Transforme une piste en preuve seulement après validation complète."""
    if company_evidence._blocked(candidate):
        return None
    if not _domain_matches_organisation(organisation, candidate):
        return None

    priority, body, about_links, final_url = company_evidence._page(candidate)
    if not priority and not body:
        return None
    evidence_url = final_url or candidate
    if company_evidence._blocked(evidence_url):
        return None
    if not _domain_matches_organisation(organisation, evidence_url):
        return None
    if not company_evidence._identity_matches(
        organisation, evidence_url, priority, body
    ):
        return None

    classified = company_evidence.classify_official_activity(priority)
    if classified is None:
        about_corpus: list[str] = []
        about_url = ""
        for link in about_links:
            p_priority, p_body, _links, p_final = company_evidence._page(link)
            if not p_priority and not p_body:
                continue
            page_url = p_final or link
            if company_evidence._blocked(page_url):
                continue
            if not _domain_matches_organisation(organisation, page_url):
                continue
            if not company_evidence._identity_matches(
                organisation, page_url, p_priority, p_body
            ):
                continue
            about_corpus.extend([p_priority, p_body[:12000]])
            if not about_url:
                about_url = page_url
        if about_corpus:
            classified = company_evidence.classify_official_activity(
                " ".join(about_corpus)
            )
            if classified is not None and about_url:
                evidence_url = about_url

    if classified is None:
        classified = company_evidence.classify_official_activity(body[:16000])
    if classified is None:
        return None

    sector, evidence_text = classified
    raw = company_evidence.CompanyEvidence(
        sector=sector,
        evidence_url=evidence_url,
        evidence_text=evidence_text,
        evidence_source=company_evidence._domain(evidence_url) or "official_site",
        evidence_type="official_site",
    )
    return strict_activity_evidence(raw)


def research_official_evidence(
    row: dict,
) -> tuple[company_evidence.CompanyEvidence | None, int]:
    """Teste des domaines déterministes et retourne aussi le coût de découverte."""
    organisation = str(row.get("organisation") or "").strip()
    if not organisation:
        return None, 0
    tested = 0
    for candidate in candidate_official_urls(row):
        tested += 1
        try:
            evidence = validate_official_candidate(organisation, candidate)
        except Exception:
            evidence = None
        if evidence is not None:
            return evidence, tested
    return None, tested


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
        "candidate_urls_tested": 0,
        "existing_evidence_kept": 0,
        "existing_evidence_rejected": 0,
        "evidence_found": 0,
        "resolved_unknown": 0,
        "corrected_known": 0,
        "verified_same": 0,
        "no_official_evidence": 0,
    }

    research_targets: list[tuple[int, dict]] = []
    for index, row in targets:
        if has_sector_evidence(row):
            strict = strict_existing_evidence(row)
            if strict is not None:
                apply_evidence(row, strict)
                stats["existing_evidence_kept"] += 1
                continue
            clear_sector_evidence(row)
            stats["existing_evidence_rejected"] += 1
        research_targets.append((index, row))

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(research_official_evidence, row): index
            for index, row in research_targets
        }
        for future in as_completed(futures):
            index = futures[future]
            try:
                evidence, tested = future.result()
            except Exception:
                evidence, tested = None, 0
            stats["candidate_urls_tested"] += tested
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
    metadata["sector_evidence_v4"] = {
        **stats,
        "method": "deterministic official domain + identity + explicit activity phrase",
        "evidence_policy": (
            "a sector keyword alone is insufficient; stored evidence must contain an explicit "
            "activity formulation recognized by Cyberwatch, then be reclassified locally"
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
        "CANDIDATES", stats["candidate_urls_tested"],
        "KEPT", stats["existing_evidence_kept"],
        "REJECTED_OLD", stats["existing_evidence_rejected"],
        "EVIDENCE", stats["evidence_found"],
        "RESOLVED", stats["resolved_unknown"],
        "NO_EVIDENCE", stats["no_official_evidence"],
        flush=True,
    )
    return stats


def main() -> None:
    for stem, source_id in DATASETS.items():
        run(stem, source_id)


if __name__ == "__main__":
    main()
