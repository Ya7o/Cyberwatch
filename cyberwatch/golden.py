"""Golden set réutilisable pour challenger la qualification Cyberwatch.

Le golden set est volontairement indépendant des sorties courantes de Cyberwatch :
les labels de référence sont versionnés séparément, tandis que le matching avec la
base courante privilégie les preuves stables (organisation, sources, date) avant
l'Incident_ID historique.
"""

from __future__ import annotations

import csv
import datetime as dt
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from . import config
from .normalize import organisation_key

PIPE = " | "
UNKNOWN = "Inconnu"
CONFIDENCE_VALUES = frozenset({"HIGH", "MEDIUM", "LOW"})
GOLDEN_ID_RE = re.compile(r"^GOLD-\d{4,}$")

GOLDEN_COLUMNS = [
    "Golden_ID",
    "Organisation",
    "Organisation_Key",
    "Reference_Date",
    "Source_IDs",
    "Source_URLs",
    "Secteur_REF",
    "Menace_REF",
    "Localisation_REF",
    "Secteur_Confidence",
    "Menace_Confidence",
    "Localisation_Confidence",
    "Secteur_Evidence",
    "Menace_Evidence",
    "Localisation_Evidence",
    "Incident_ID_Snapshot",
    "Reviewed_At",
    "Golden_Version",
    "Taxonomy_Version",
]

CANDIDATE_COLUMNS = [
    "Incident_ID",
    "Date",
    "Organisation",
    "Organisation_Key",
    "Sources",
    "Source_URLs",
]

DETAIL_COLUMNS = [
    "Golden_ID",
    "Organisation",
    "Reference_Date",
    "Match_Status",
    "Match_Strategy",
    "Incident_ID_Snapshot",
    "Incident_ID_Current",
    "Secteur_REF",
    "Secteur_CW",
    "Secteur_Match",
    "Menace_REF",
    "Menace_CW",
    "Menace_Match",
    "Localisation_REF",
    "Localisation_CW",
    "Localisation_Match",
]

REFERENCE_FIELDS = (
    ("Secteur", "Secteur_REF", "Secteur", config.SECTOR_UNKNOWN),
    ("Menace", "Menace_REF", "Menace", config.THREAT_UNKNOWN),
    ("Localisation", "Localisation_REF", "Localisation", config.LOC_INCONNU),
)


@dataclass(frozen=True)
class MatchResult:
    status: str
    strategy: str = ""
    incident: dict[str, str] | None = None


def read_csv(path: Path | str) -> list[dict[str, str]]:
    with Path(path).open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path | str, rows: list[dict[str, object]], columns: list[str]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _split_multi(value: str) -> set[str]:
    return {part.strip() for part in str(value or "").split("|") if part.strip()}


def _iso_date(value: str) -> dt.date | None:
    try:
        return dt.date.fromisoformat(str(value or "").strip())
    except ValueError:
        return None


def blind_candidates(incidents: list[dict[str, str]]) -> list[dict[str, str]]:
    """Produit une vue aveugle sans exposer Secteur/Menace/Localisation."""
    rows = []
    for incident in incidents:
        organisation = (incident.get("Organisation") or "").strip()
        rows.append({
            "Incident_ID": incident.get("Incident_ID", ""),
            "Date": incident.get("Date", ""),
            "Organisation": organisation,
            "Organisation_Key": organisation_key(organisation),
            "Sources": incident.get("Sources", ""),
            "Source_URLs": incident.get("Source_URLs", ""),
        })
    return sorted(rows, key=lambda row: (row["Date"], row["Organisation_Key"], row["Incident_ID"]))


def validate_header(path: Path | str) -> list[str]:
    with Path(path).open(encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader, [])
    return [] if header == GOLDEN_COLUMNS else [
        f"header golden invalide: attendu {GOLDEN_COLUMNS}, obtenu {header}"
    ]


def validate_golden(rows: list[dict[str, str]], *, require_current_taxonomy: bool = True) -> list[str]:
    """Valide le contrat du golden set sans consulter la base de production."""
    problems: list[str] = []
    seen_ids: set[str] = set()
    seen_identity: set[tuple[str, str, tuple[str, ...]]] = set()

    for index, row in enumerate(rows, start=2):
        prefix = f"ligne {index}"
        golden_id = (row.get("Golden_ID") or "").strip()
        if not GOLDEN_ID_RE.match(golden_id):
            problems.append(f"{prefix}: Golden_ID invalide ({golden_id!r})")
        elif golden_id in seen_ids:
            problems.append(f"{prefix}: Golden_ID dupliqué ({golden_id})")
        seen_ids.add(golden_id)

        organisation = (row.get("Organisation") or "").strip()
        org_key = (row.get("Organisation_Key") or "").strip()
        if not organisation:
            problems.append(f"{prefix}: Organisation vide")
        if not org_key:
            problems.append(f"{prefix}: Organisation_Key vide")

        reference_date = (row.get("Reference_Date") or "").strip()
        if _iso_date(reference_date) is None:
            problems.append(f"{prefix}: Reference_Date invalide ({reference_date!r})")

        source_ids = _split_multi(row.get("Source_IDs", ""))
        source_urls = _split_multi(row.get("Source_URLs", ""))
        if not source_ids and not source_urls:
            problems.append(f"{prefix}: aucune source de référence")

        identity = (org_key, reference_date, tuple(sorted(source_urls)))
        if identity in seen_identity and source_urls:
            problems.append(f"{prefix}: incident de référence dupliqué")
        seen_identity.add(identity)

        allowed = {
            "Secteur_REF": set(config.SECTORS),
            "Menace_REF": set(config.THREATS),
            "Localisation_REF": set(config.LOCATIONS),
        }
        for field, values in allowed.items():
            value = (row.get(field) or "").strip()
            if value not in values:
                problems.append(f"{prefix}: {field} hors nomenclature ({value!r})")

        for field in ("Secteur", "Menace", "Localisation"):
            confidence = (row.get(f"{field}_Confidence") or "").strip()
            if confidence not in CONFIDENCE_VALUES:
                problems.append(f"{prefix}: {field}_Confidence invalide ({confidence!r})")
            ref_value = (row.get(f"{field}_REF") or "").strip()
            evidence = (row.get(f"{field}_Evidence") or "").strip()
            if ref_value != UNKNOWN and not evidence:
                problems.append(f"{prefix}: {field}_Evidence requis pour une valeur qualifiée")

        reviewed_at = (row.get("Reviewed_At") or "").strip()
        if _iso_date(reviewed_at) is None:
            problems.append(f"{prefix}: Reviewed_At invalide ({reviewed_at!r})")

        version = (row.get("Golden_Version") or "").strip()
        try:
            if int(version) < 1:
                raise ValueError
        except ValueError:
            problems.append(f"{prefix}: Golden_Version invalide ({version!r})")

        taxonomy = (row.get("Taxonomy_Version") or "").strip()
        if not taxonomy:
            problems.append(f"{prefix}: Taxonomy_Version vide")
        elif require_current_taxonomy and taxonomy != config.METHOD_ID:
            problems.append(
                f"{prefix}: Taxonomy_Version={taxonomy!r} != METHOD_ID={config.METHOD_ID!r}; revue requise"
            )

    return problems


def validate_file(path: Path | str, *, require_current_taxonomy: bool = True) -> list[str]:
    problems = validate_header(path)
    if problems:
        return problems
    return validate_golden(read_csv(path), require_current_taxonomy=require_current_taxonomy)


def _candidate_score(golden: dict[str, str], incident: dict[str, str]) -> tuple[int, int, int] | None:
    current_key = organisation_key(incident.get("Organisation", ""))
    golden_keys = {
        (golden.get("Organisation_Key") or "").strip(),
        organisation_key(golden.get("Organisation", "")),
    }
    golden_keys.discard("")
    if not current_key or current_key not in golden_keys:
        return None

    gold_urls = _split_multi(golden.get("Source_URLs", ""))
    incident_urls = _split_multi(incident.get("Source_URLs", ""))
    url_overlap = len(gold_urls & incident_urls)

    gold_sources = _split_multi(golden.get("Source_IDs", ""))
    incident_sources = _split_multi(incident.get("Sources", ""))
    source_overlap = len(gold_sources & incident_sources)

    gold_date = _iso_date(golden.get("Reference_Date", ""))
    incident_date = _iso_date(incident.get("Date", ""))
    days = abs((gold_date - incident_date).days) if gold_date and incident_date else 999999

    if url_overlap:
        return (3, url_overlap, -days)
    if source_overlap and days <= config.INCIDENT_GAP_DAYS:
        return (2, source_overlap, -days)
    if days <= 3:
        return (1, 0, -days)
    return None


def match_golden(golden: dict[str, str], incidents: list[dict[str, str]]) -> MatchResult:
    """Retrouve le même cas même si l'Incident_ID a changé après déduplication."""
    snapshot_id = (golden.get("Incident_ID_Snapshot") or "").strip()
    if snapshot_id:
        direct = [row for row in incidents if row.get("Incident_ID") == snapshot_id]
        if len(direct) == 1 and _candidate_score(golden, direct[0]) is not None:
            return MatchResult("MATCHED", "snapshot_id", direct[0])

    scored: list[tuple[tuple[int, int, int], dict[str, str]]] = []
    for incident in incidents:
        score = _candidate_score(golden, incident)
        if score is not None:
            scored.append((score, incident))
    if not scored:
        return MatchResult("MISSING")

    scored.sort(key=lambda pair: (pair[0], pair[1].get("Incident_ID", "")), reverse=True)
    best_score = scored[0][0]
    best = [incident for score, incident in scored if score == best_score]
    if len(best) != 1:
        return MatchResult("AMBIGUOUS")

    strategy = {3: "source_url", 2: "source_and_date", 1: "organisation_and_date"}[best_score[0]]
    return MatchResult("MATCHED", strategy, best[0])


def evaluate(golden_rows: list[dict[str, str]], incidents: list[dict[str, str]]) -> dict[str, object]:
    details: list[dict[str, object]] = []
    matched = 0
    ambiguous = 0
    missing = 0

    for golden in golden_rows:
        result = match_golden(golden, incidents)
        if result.status == "MATCHED":
            matched += 1
        elif result.status == "AMBIGUOUS":
            ambiguous += 1
        else:
            missing += 1

        incident = result.incident or {}
        detail: dict[str, object] = {
            "Golden_ID": golden.get("Golden_ID", ""),
            "Organisation": golden.get("Organisation", ""),
            "Reference_Date": golden.get("Reference_Date", ""),
            "Match_Status": result.status,
            "Match_Strategy": result.strategy,
            "Incident_ID_Snapshot": golden.get("Incident_ID_Snapshot", ""),
            "Incident_ID_Current": incident.get("Incident_ID", ""),
        }
        for label, ref_field, current_field, _unknown in REFERENCE_FIELDS:
            ref = golden.get(ref_field, "")
            current = incident.get(current_field, "") if result.status == "MATCHED" else ""
            detail[ref_field] = ref
            detail[f"{label}_CW"] = current
            detail[f"{label}_Match"] = result.status == "MATCHED" and current == ref
        details.append(detail)

    field_summaries: dict[str, dict[str, object]] = {}
    matched_details = [row for row in details if row["Match_Status"] == "MATCHED"]
    for label, ref_field, _current_field, unknown in REFERENCE_FIELDS:
        total = len(matched_details)
        qualified = sum(row[f"{label}_CW"] != unknown for row in matched_details)
        correct = sum(bool(row[f"{label}_Match"]) for row in matched_details)
        correct_when_qualified = sum(
            bool(row[f"{label}_Match"]) and row[f"{label}_CW"] != unknown
            for row in matched_details
        )
        resolvable_unknown = sum(
            row[f"{label}_CW"] == unknown and row[ref_field] != unknown
            for row in matched_details
        )
        wrong_classification = sum(
            row[f"{label}_CW"] != unknown and row[f"{label}_CW"] != row[ref_field]
            for row in matched_details
        )
        field_summaries[label] = {
            "matched_cases": total,
            "correct": correct,
            "accuracy_pct": round(100.0 * correct / total, 1) if total else 0.0,
            "qualified": qualified,
            "coverage_pct": round(100.0 * qualified / total, 1) if total else 0.0,
            "precision_when_qualified_pct": (
                round(100.0 * correct_when_qualified / qualified, 1) if qualified else 0.0
            ),
            "resolvable_unknown": resolvable_unknown,
            "wrong_classification": wrong_classification,
            "reference_unknown": sum(row[ref_field] == unknown for row in matched_details),
        }

    return {
        "cases": len(golden_rows),
        "matched": matched,
        "ambiguous": ambiguous,
        "missing": missing,
        "fields": field_summaries,
        "details": details,
    }


def group_candidates_round_robin(
    rows: list[dict[str, str]], *, limit: int | None = None
) -> list[dict[str, str]]:
    """Échantillonnage déterministe qui évite qu'une source dominante écrase les autres."""
    if limit is None or limit <= 0 or limit >= len(rows):
        return list(rows)

    groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        sources = sorted(_split_multi(row.get("Sources", "")))
        bucket = sources[0] if sources else "NO_SOURCE"
        groups[bucket].append(row)
    for bucket_rows in groups.values():
        bucket_rows.sort(key=lambda row: (row.get("Date", ""), row.get("Incident_ID", "")), reverse=True)

    selected: list[dict[str, str]] = []
    buckets = sorted(groups)
    index = 0
    while len(selected) < limit:
        progressed = False
        for bucket in buckets:
            if index < len(groups[bucket]):
                selected.append(groups[bucket][index])
                progressed = True
                if len(selected) == limit:
                    break
        if not progressed:
            break
        index += 1
    return selected
