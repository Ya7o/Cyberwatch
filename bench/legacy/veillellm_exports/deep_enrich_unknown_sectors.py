#!/usr/bin/env python3
"""Enrichit les secteurs challengers depuis l'activité principale officielle.

La découverte reste déterministe : domaines explicitement cités ou dérivés du
nom de l'organisation. Une URL candidate n'est qu'une piste ; la page doit
valider l'identité de l'organisation puis contenir une formulation décrivant son
activité principale.

Les formulations de fonction secondaire sont volontairement exclues. Ainsi un
« centre de formation » interne, un « fournisseur de l'hébergement du site » ou
un « éditeur de la plateforme » ne peuvent plus définir le secteur de la
victime. La précision prime sur la couverture : en cas de doute, ``Inconnu``.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import company_evidence, config  # noqa: E402
from cyberwatch.normalize import classify_sector, searchable  # noqa: E402

OUT = Path(__file__).resolve().parent
ITEMS_CSV = ROOT / "data" / "items.csv"

DATASETS = {
    "cyberattaque_org_2026": "CYBERATTAQUE_ORG",
    "frenchbreaches_2026": "FRENCHBREACHES",
}

COLS = [
    "date", "organisation", "territoire", "localisation", "secteur",
    "type_menace", "acteur", "statut", "score_cyberattaque", "impact_connu",
    "source_urls", "synthese", "evolution", "sector_evidence_url",
    "sector_evidence_text", "sector_evidence_source", "sector_evidence_type",
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

# Contrairement à normalize.extract_activity_description, ce garde n'accepte
# pas les groupes nominaux comme « centre de formation » : ils décrivent trop
# souvent une fonction secondaire d'une entreprise dont le métier est autre.
_PRIMARY_ACTIVITY_RE = re.compile(
    r"\b(?:sp[ée]cialis[ée]e?\s+dans|[ée]diteur\s+de|acteur\s+de|"
    r"fournisseur\s+de|fabricant\s+de|distributeur\s+de|enseigne\s+de)"
    r"\s+([^,.;:\n]{3,100})",
    re.I,
)

# Une locution grammaticalement valide peut décrire la plomberie du site ou
# une fonction support. Ces marqueurs la rendent inadmissible comme métier de la
# victime. Ils sont testés sur texte normalisé/désaccentué.
_SECONDARY_ACTIVITY_MARKERS = (
    "hebergement du site",
    "hebergement de ce site",
    "hebergement de la plateforme",
    "hebergement du portail",
    "fournisseur de l hebergement",
    "editeur de la plateforme",
    "editeur du site",
    "editeur de ce site",
    "directeur de la publication",
    "credits photos",
    "credit photos",
    "banque d images",
)


def _url_values(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(part).strip() for part in value if str(part).strip()]
    if isinstance(value, str):
        return [part.strip() for part in value.split("|") if part.strip()]
    return []


def incident_urls(row: dict) -> tuple[str, ...]:
    values = row.get("sources") or row.get("source_urls") or []
    return tuple(dict.fromkeys(_url_values(values)))


def target_unknown_urls(source_id: str, path: Path = ITEMS_CSV) -> set[str]:
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
    # Les preuves déjà appliquées sont toujours réauditées lors d'un changement
    # de politique, même si le secteur canonique n'est donc plus Inconnu.
    return bool(target_urls.intersection(incident_urls(row))) or has_sector_evidence(row)


def clear_sector_evidence(row: dict) -> None:
    for field in SECTOR_EVIDENCE_FIELDS:
        row.pop(field, None)
    row["secteur"] = config.SECTOR_UNKNOWN


def apply_evidence(
    row: dict,
    evidence: company_evidence.CompanyEvidence,
) -> tuple[str, str]:
    before = str(row.get("secteur") or config.SECTOR_UNKNOWN)
    row["secteur"] = evidence.sector
    row["sector_evidence_url"] = evidence.evidence_url
    row["sector_evidence_text"] = evidence.evidence_text
    row["sector_evidence_source"] = evidence.evidence_source
    row["sector_evidence_type"] = "official_primary_activity"
    if before != evidence.sector and row.get("evolution") != "nouveau":
        row["evolution"] = "enrichi"
    return before, evidence.sector


def extract_primary_activity_description(text: str) -> str:
    """Extrait uniquement une locution susceptible de décrire le métier cœur."""
    if not text:
        return ""
    match = _PRIMARY_ACTIVITY_RE.search(text)
    if not match:
        return ""
    activity = match.group(0).strip()
    blob = searchable(activity)
    if any(marker in blob for marker in _SECONDARY_ACTIVITY_MARKERS):
        return ""
    return activity


def classify_primary_activity(activity: str) -> str:
    """Classe la locution métier, avec quelques synonymes métier non ambigus."""
    blob = searchable(activity)
    if not blob:
        return config.SECTOR_UNKNOWN

    # « transition énergétique » ne contient pas le token exact « énergie » et
    # tombait auparavant sur « foncier » => BTP. Ici la formulation métier est
    # suffisamment explicite pour rendre l'énergie prioritaire.
    if any(
        marker in blob
        for marker in (
            "transition energetique",
            "energies renouvelables",
            "energie renouvelable",
            "production energetique",
        )
    ):
        return config.SECTOR_ENERGY

    return classify_sector(activity)


def strict_activity_evidence(
    evidence: company_evidence.CompanyEvidence,
) -> company_evidence.CompanyEvidence | None:
    activity = extract_primary_activity_description(evidence.evidence_text)
    if not activity:
        return None
    sector = classify_primary_activity(activity)
    if sector == config.SECTOR_UNKNOWN:
        return None
    return company_evidence.CompanyEvidence(
        sector=sector,
        evidence_url=evidence.evidence_url,
        evidence_text=activity,
        evidence_source=evidence.evidence_source,
        evidence_type="official_primary_activity",
    )


def _primary_activity_from_text(
    text: str,
    evidence_url: str,
) -> company_evidence.CompanyEvidence | None:
    activity = extract_primary_activity_description(text)
    if not activity:
        return None
    sector = classify_primary_activity(activity)
    if sector == config.SECTOR_UNKNOWN:
        return None
    return company_evidence.CompanyEvidence(
        sector=sector,
        evidence_url=evidence_url,
        evidence_text=activity,
        evidence_source=company_evidence._domain(evidence_url) or "official_site",
        evidence_type="official_primary_activity",
    )


def strict_existing_evidence(row: dict) -> company_evidence.CompanyEvidence | None:
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
    return [
        token
        for token in searchable(organisation).split()
        if len(token) > 1 and token not in _LEGAL_SUFFIXES
    ][:6]


def candidate_official_urls(row: dict) -> tuple[str, ...]:
    values: list[str] = []
    discovery_text = " ".join(
        str(row.get(field) or "")
        for field in ("organisation", "impact_connu", "synthese")
    )
    for match in _DOMAIN_RE.finditer(discovery_text):
        values.append("https://" + match.group(1).lower())

    tokens = _domain_guess_tokens(str(row.get("organisation") or "").strip())
    if tokens:
        slugs: list[str] = []
        for slug in ("-".join(tokens), "".join(tokens)):
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


def _validated_page(
    organisation: str,
    url: str,
) -> tuple[str, str, list[str], str] | None:
    priority, body, links, final_url = company_evidence._page(url)
    if not priority and not body:
        return None
    page_url = final_url or url
    if company_evidence._blocked(page_url):
        return None
    if not _domain_matches_organisation(organisation, page_url):
        return None
    if not company_evidence._identity_matches(organisation, page_url, priority, body):
        return None
    return priority, body, links, page_url


def validate_official_candidate(
    organisation: str,
    candidate: str,
) -> company_evidence.CompanyEvidence | None:
    if company_evidence._blocked(candidate):
        return None
    if not _domain_matches_organisation(organisation, candidate):
        return None

    first = _validated_page(organisation, candidate)
    if first is None:
        return None
    priority, body, about_links, evidence_url = first

    evidence = _primary_activity_from_text(priority, evidence_url)
    if evidence is not None:
        return evidence

    for link in about_links:
        page = _validated_page(organisation, link)
        if page is None:
            continue
        p_priority, p_body, _links, page_url = page
        evidence = _primary_activity_from_text(
            " ".join(part for part in (p_priority, p_body[:12000]) if part),
            page_url,
        )
        if evidence is not None:
            return evidence

    return _primary_activity_from_text(body[:16000], evidence_url)


def research_official_evidence(
    row: dict,
) -> tuple[company_evidence.CompanyEvidence | None, int]:
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
    metadata["sector_evidence_v5"] = {
        **stats,
        "method": "official domain + identity + primary activity formulation",
        "evidence_policy": (
            "secondary functions and website/legal boilerplate are inadmissible; "
            "uncertain activity remains Inconnu"
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
