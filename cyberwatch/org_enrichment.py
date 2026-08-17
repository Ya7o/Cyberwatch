"""Enrichissement gratuit d'entreprise pour ``Sector`` et ``Location``.

Ordre de preuve :
1. registre public français avec identité exacte et SIREN unique ;
2. pour les identités non résolues ou trop risquées, site officiel découvert de
   manière ciblée par :mod:`cyberwatch.company_evidence`.

Les moteurs de recherche ne sont jamais des preuves : ils servent uniquement à
trouver une page officielle. Aucun fuzzy matching n'est utilisé. Les identités
courtes de type acronyme ne sont jamais validées par le seul fait qu'une société
homonyme existe au registre.
"""

from __future__ import annotations

import os
import time
from dataclasses import asdict, dataclass, field, fields

import requests

from . import company_evidence, config, store
from .normalize import organisation_key, searchable

ORG_ENRICHMENT_URL = "https://recherche-entreprises.api.gouv.fr/search"
ORG_ENRICHMENT_RESULTS_PER_QUERY = 5

NAF_SECTIONS: dict[str, tuple[str, str]] = {
    "A": ("Agriculture, sylviculture et pêche", config.SECTOR_UNKNOWN),
    "B": ("Industries extractives", config.SECTOR_UNKNOWN),
    "C": ("Industrie manufacturière", config.SECTOR_INDUSTRY),
    "D": (
        "Production et distribution d'électricité, de gaz, de vapeur et d'air conditionné",
        config.SECTOR_ENERGY,
    ),
    "E": (
        "Production et distribution d'eau ; assainissement, gestion des déchets et dépollution",
        config.SECTOR_ENERGY,
    ),
    "F": ("Construction", config.SECTOR_CONSTRUCTION),
    "G": ("Commerce ; réparation d'automobiles et de motocycles", config.SECTOR_RETAIL),
    "H": ("Transports et entreposage", config.SECTOR_TRANSPORT),
    "I": ("Hébergement et restauration", config.SECTOR_UNKNOWN),
    "J": ("Information et communication", config.SECTOR_TECH),
    "K": ("Activités financières et d'assurance", config.SECTOR_FINANCE),
    # Mapping conservé pour compatibilité des consommateurs historiques du
    # libellé seul. Les records issus du registre ne transmettent plus cette
    # section au pipeline Sector (voir AMBIGUOUS_NAF_SECTIONS ci-dessous).
    "L": ("Activités immobilières", config.SECTOR_CONSTRUCTION),
    "M": ("Activités spécialisées, scientifiques et techniques", config.SECTOR_SERVICES),
    "N": ("Activités de services administratifs et de soutien", config.SECTOR_SERVICES),
    "O": ("Administration publique", config.SECTOR_ADMIN),
    "P": ("Enseignement", config.SECTOR_EDUCATION),
    "Q": ("Santé humaine et action sociale", config.SECTOR_HEALTH),
    "R": ("Arts, spectacles et activités récréatives", config.SECTOR_UNKNOWN),
    "S": ("Autres activités de services", config.SECTOR_UNKNOWN),
    "T": ("Activités des ménages en tant qu'employeurs", config.SECTOR_UNKNOWN),
    "U": ("Activités extra-territoriales", config.SECTOR_UNKNOWN),
}

# Une section NAF peut décrire la société juridique trouvée sans décrire le
# métier de la marque victime. Le cas McDonald's France (section L) a produit un
# faux BTP réel. Ces sections restent utilisables comme métadonnées mais ne sont
# plus exposées comme preuve d'activité au pipeline Sector.
AMBIGUOUS_NAF_SECTIONS = frozenset({"L"})

NAF_SECTION_LABELS: dict[str, str] = {
    letter: label for letter, (label, _sector) in NAF_SECTIONS.items()
}
_LABEL_TO_SECTOR: dict[str, str] = {
    label: sector for label, sector in NAF_SECTIONS.values()
}


def sector_for_activity_label(activity_label: str) -> str:
    """Retourne le mapping historique d'un libellé NAF déjà validé.

    Les sections trop larges issues directement du registre sont filtrées avant
    cet appel dans ``_record_from_candidate``.
    """
    return _LABEL_TO_SECTOR.get(activity_label, config.SECTOR_UNKNOWN)


def location_for_headquarters_department(department: str) -> str:
    """Mappe uniquement les départements couverts sans extrapolation."""
    value = str(department or "").strip().upper()
    if value == "974":
        return config.LOC_REUNION
    if value == "976":
        return config.LOC_MAYOTTE
    if value in {"2A", "2B"}:
        return config.LOC_FRANCE
    if value.isdigit() and 1 <= int(value) <= 95:
        return config.LOC_FRANCE
    return config.LOC_INCONNU


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if not value:
        return default
    return value.strip() not in ("0", "false", "False", "")


ORG_ENRICHMENT_TIMEOUT_SECONDS = _env_int("ORG_ENRICHMENT_TIMEOUT_SECONDS", 10)
ORG_ENRICHMENT_MAX_RETRIES = _env_int("ORG_ENRICHMENT_MAX_RETRIES", 1)

# Version 4 : invalidation ciblée des anciens matches d'acronymes et remise à
# zéro des validations calculées avec les anciens mappings NAF.
ORG_ENRICHMENT_CACHE_VERSION = "4"

MATCHED = "MATCHED"
AMBIGUOUS = "AMBIGUOUS"
NOT_FOUND = "NOT_FOUND"
ERROR = "ERROR"


class OrgEnrichmentError(Exception):
    """Échec réseau, HTTP ou format du registre public."""


@dataclass
class OrgEnrichmentRecord:
    """Une ligne du cache ``data/org_enrichment_cache.csv``."""

    Organisation_Key: str
    Query_Name: str
    Matched_Name: str = ""
    Company_ID: str = ""
    Activity_Code: str = ""
    Activity_Label: str = ""
    Headquarters_Department: str = ""
    Evidence_Source: str = "recherche-entreprises.api.gouv.fr"
    Evidence_URL: str = ""
    Match_Status: str = ""
    Fetched_At: str = ""
    Validated_Sector: str = ""
    Validated_Via: str = ""
    Cache_Version: str = ""


@dataclass
class OrgEnrichmentState:
    enabled: bool = False
    max_calls: int = 200
    official_site_max_calls: int = 60
    cache: dict[str, dict] = field(default_factory=dict)

    calls_attempted: int = 0
    calls_matched: int = 0
    calls_ambiguous: int = 0
    calls_not_found: int = 0
    calls_error: int = 0
    cache_hits: int = 0
    duration_seconds: float = 0.0
    official_site_attempted: int = 0
    official_site_matched: int = 0


def _identity_requires_confirmation(query_name: str) -> bool:
    """Détecte les identités trop faibles pour qu'une homonymie registre suffise.

    Le test porte sur le libellé brut, avant ``organisation_key`` : un alias
    versionné peut développer ENSAM en « École nationale... », mais cela ne doit
    pas masquer le fait que la requête envoyée au registre était un acronyme.
    """
    raw = str(query_name or "").strip()
    raw_normalized = searchable(raw)
    raw_tokens = raw_normalized.split()
    if not raw_tokens:
        return False

    compact = "".join(ch for ch in raw if ch.isalnum())
    letters = "".join(ch for ch in compact if ch.isalpha())
    is_single_token = len(raw_tokens) == 1
    is_upper_acronym = (
        is_single_token
        and bool(letters)
        and letters.upper() == letters
        and 2 <= len(letters) <= 12
    )
    is_very_short = is_single_token and len(raw_normalized) <= 4
    return is_upper_acronym or is_very_short


def _ambiguous_activity_label(activity_label: str) -> bool:
    return activity_label in {
        NAF_SECTION_LABELS[section]
        for section in AMBIGUOUS_NAF_SECTIONS
        if section in NAF_SECTION_LABELS
    }


def start_state() -> OrgEnrichmentState:
    state = OrgEnrichmentState(
        enabled=_env_bool("ORG_ENRICHMENT_ENABLED", True),
        max_calls=_env_int("ORG_ENRICHMENT_MAX_CALLS_PER_RUN", 200),
        official_site_max_calls=_env_int("ORG_OFFICIAL_SITE_MAX_CALLS_PER_RUN", 60),
    )
    if not state.enabled:
        return state

    for row in store.load_org_enrichment_cache():
        key = row.get("Organisation_Key", "")
        if not key:
            continue
        if row.get("Cache_Version") != ORG_ENRICHMENT_CACHE_VERSION:
            # Les négatifs sont retentés à chaque changement de politique. Les
            # anciens matches d'acronymes sont eux aussi invalidés : ils ont été
            # obtenus avec une politique d'identité désormais jugée insuffisante.
            if row.get("Match_Status") in (NOT_FOUND, AMBIGUOUS):
                continue
            if _identity_requires_confirmation(row.get("Query_Name", "")):
                continue
            row = dict(row)
            row["Validated_Sector"] = ""
            row["Validated_Via"] = ""
            # Un ancien cache peut contenir la section L comme preuve Sector ;
            # elle doit être neutralisée lors de la migration v4.
            if _ambiguous_activity_label(row.get("Activity_Label", "")):
                row["Activity_Label"] = ""
            row["Cache_Version"] = ORG_ENRICHMENT_CACHE_VERSION
        state.cache[key] = row
    return state


def _fetch(query_name: str, state: OrgEnrichmentState) -> dict:
    params = {"q": query_name, "per_page": ORG_ENRICHMENT_RESULTS_PER_QUERY}
    attempt = 0
    while True:
        try:
            response = requests.get(
                ORG_ENRICHMENT_URL,
                params=params,
                timeout=ORG_ENRICHMENT_TIMEOUT_SECONDS,
            )
        except requests.RequestException as exc:
            attempt += 1
            if attempt > ORG_ENRICHMENT_MAX_RETRIES:
                raise OrgEnrichmentError(f"réseau: {type(exc).__name__}") from exc
            time.sleep(2 ** attempt)
            continue

        if response.status_code == 200:
            try:
                payload = response.json()
            except ValueError as exc:
                raise OrgEnrichmentError(f"JSON invalide: {exc}") from exc
            if not isinstance(payload, dict):
                raise OrgEnrichmentError("réponse JSON non conforme (pas un objet)")
            return payload
        if response.status_code == 429 or 500 <= response.status_code < 600:
            attempt += 1
            if attempt > ORG_ENRICHMENT_MAX_RETRIES:
                raise OrgEnrichmentError(f"HTTP {response.status_code} après retries")
            time.sleep(2 ** attempt)
            continue
        raise OrgEnrichmentError(f"HTTP {response.status_code}: {response.text[:200]}")


def _candidate_names(candidate: dict) -> list[str]:
    """Noms explicitement fournis par l'API, sans rapprochement approximatif."""
    names: list[str] = []

    def add(value) -> None:
        text = str(value or "").strip()
        if text and text not in names:
            names.append(text)

    add(candidate.get("nom_raison_sociale"))
    add(candidate.get("nom_commercial"))
    for field_name in ("noms_commerciaux", "noms_enseignes"):
        values = candidate.get(field_name) or []
        if isinstance(values, list):
            for value in values:
                add(value)
    complete = str(candidate.get("nom_complet") or "").strip()
    add(complete)
    if complete.endswith(")") and "(" in complete:
        add(complete.rsplit("(", 1)[0].strip())
    return names


def _match(query_name: str, payload: dict) -> tuple[str, dict]:
    """Match exact raison sociale/nom commercial, avec SIREN unique."""
    query_key = organisation_key(query_name)
    if not query_key:
        return NOT_FOUND, {}

    results = payload.get("results")
    if not isinstance(results, list):
        return NOT_FOUND, {}

    exact = []
    for candidate in results:
        if not isinstance(candidate, dict):
            continue
        if any(organisation_key(name) == query_key for name in _candidate_names(candidate)):
            exact.append(candidate)

    if not exact:
        return NOT_FOUND, {}

    distinct_sirens = {str(candidate.get("siren") or "").strip() for candidate in exact}
    if "" in distinct_sirens or len(distinct_sirens) > 1:
        return AMBIGUOUS, {}
    return MATCHED, exact[0]


def _record_from_candidate(
    org_key: str,
    query_name: str,
    candidate: dict,
    fetched_at: str,
) -> OrgEnrichmentRecord:
    activity_code = str(candidate.get("activite_principale") or "")
    section = str(candidate.get("section_activite_principale") or "")
    activity_label = (
        "" if section in AMBIGUOUS_NAF_SECTIONS
        else NAF_SECTION_LABELS.get(section, "")
    )
    headquarters = candidate.get("siege")
    headquarters_department = (
        str(headquarters.get("departement") or "")
        if isinstance(headquarters, dict)
        else ""
    )
    matched_name = str(
        candidate.get("nom_raison_sociale") or candidate.get("nom_complet") or ""
    )
    siren = str(candidate.get("siren") or "")
    return OrgEnrichmentRecord(
        Organisation_Key=org_key,
        Query_Name=query_name,
        Matched_Name=matched_name,
        Company_ID=siren,
        Activity_Code=activity_code,
        Activity_Label=activity_label,
        Headquarters_Department=headquarters_department,
        Evidence_URL=(f"{ORG_ENRICHMENT_URL}?q={siren}" if siren else ""),
        Match_Status=MATCHED,
        Fetched_At=fetched_at,
        Cache_Version=ORG_ENRICHMENT_CACHE_VERSION,
    )


def _record_from_official_evidence(
    org_key: str,
    query_name: str,
    fetched_at: str,
    evidence: company_evidence.CompanyEvidence,
) -> OrgEnrichmentRecord:
    return OrgEnrichmentRecord(
        Organisation_Key=org_key,
        Query_Name=query_name,
        Matched_Name=query_name,
        Activity_Label=evidence.evidence_text,
        Evidence_Source=evidence.evidence_source,
        Evidence_URL=evidence.evidence_url,
        Match_Status=MATCHED,
        Fetched_At=fetched_at,
        Validated_Sector=evidence.sector,
        Validated_Via=evidence.evidence_type,
        Cache_Version=ORG_ENRICHMENT_CACHE_VERSION,
    )


def _official_site_fallback(
    org_key: str,
    organisation_raw: str,
    fetched_at: str,
    state: OrgEnrichmentState,
) -> tuple[bool, OrgEnrichmentRecord | None]:
    """Retourne ``(tenté, record)`` sans figer un budget épuisé."""
    if state.official_site_attempted >= state.official_site_max_calls:
        return False, None

    state.official_site_attempted += 1
    evidence = company_evidence.resolve_official_site(organisation_raw)
    if evidence is None:
        return True, None

    state.official_site_matched += 1
    state.calls_matched += 1
    return True, _record_from_official_evidence(
        org_key,
        organisation_raw,
        fetched_at,
        evidence,
    )


def resolve(
    org_key: str,
    organisation_raw: str,
    fetched_at: str,
    state: OrgEnrichmentState,
) -> OrgEnrichmentRecord | None:
    """Résout l'organisation sans jamais lever d'exception.

    Une panne registre reste une ERROR non cachée. Les NOT_FOUND/AMBIGUOUS et
    les matches exacts d'identités à risque peuvent tenter le site officiel.
    """
    if not state.enabled or not org_key or not organisation_raw:
        return None

    cached = state.cache.get(org_key)
    if cached is not None:
        state.cache_hits += 1
        return OrgEnrichmentRecord(
            **{field_.name: cached.get(field_.name, "") for field_ in fields(OrgEnrichmentRecord)}
        )

    if state.calls_attempted >= state.max_calls:
        return None

    state.calls_attempted += 1
    started = time.monotonic()
    try:
        payload = _fetch(organisation_raw, state)
    except OrgEnrichmentError:
        state.calls_error += 1
        state.duration_seconds += time.monotonic() - started
        return None
    state.duration_seconds += time.monotonic() - started

    status, candidate = _match(organisation_raw, payload)
    risky_match = status == MATCHED and _identity_requires_confirmation(organisation_raw)
    if status == MATCHED and not risky_match:
        state.calls_matched += 1
        record = _record_from_candidate(org_key, organisation_raw, candidate, fetched_at)
        state.cache[org_key] = asdict(record)
        return record

    # Un acronyme homonyme est traité comme ambigu tant qu'une preuve officielle
    # ne confirme pas l'identité métier de l'organisation visée.
    fallback_status = AMBIGUOUS if risky_match else status
    attempted, official_record = _official_site_fallback(
        org_key, organisation_raw, fetched_at, state
    )
    if official_record is not None:
        state.cache[org_key] = asdict(official_record)
        return official_record

    if not attempted:
        return None

    if fallback_status == AMBIGUOUS:
        state.calls_ambiguous += 1
    else:
        state.calls_not_found += 1

    record = OrgEnrichmentRecord(
        Organisation_Key=org_key,
        Query_Name=organisation_raw,
        Match_Status=fallback_status,
        Fetched_At=fetched_at,
        Cache_Version=ORG_ENRICHMENT_CACHE_VERSION,
    )
    state.cache[org_key] = asdict(record)
    return record
