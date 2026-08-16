"""Enrichissement gratuit d'entreprise réutilisé pour `Sector` et `Location` (§12 METHODOLOGY.md).

Quand le contexte source ne décrit pas l'activité de l'organisation, ce
module interroge l'API publique française `recherche-entreprises.api.gouv.fr`
(gratuite, sans clé) pour obtenir un libellé d'activité officiel — jamais
pour deviner un secteur lui-même, seulement pour fournir au filet de
rattrapage LLM (`ai.py`) une description métier explicite à classifier.

Aucune correspondance floue n'est tentée : un candidat n'est retenu que si
son nom normalisé (`normalize.organisation_key`) est **exactement** égal à
celui recherché, via la raison sociale ou un nom commercial explicite.
Plusieurs entités légales distinctes partageant ce même nom normalisé donnent
`AMBIGUOUS`, jamais un choix arbitraire.

Comme `ai.py::_call_openai`, l'appel HTTP est indépendant de
`cyberwatch/http.py` (`HttpClient`/`Budget`) : la dimension de budget ici est
un nombre d'appels par run, pas du respect de robots.txt ou de politesse
inter-hôtes propre à un collecteur.

Schéma réel vérifié le 2026-08-15 via un run GitHub Actions (le domaine est
hors politique réseau du bac à sable de développement, `probe-org-schema`
dans `bench-qualification.yml`) : chaque résultat porte `siren`,
`nom_complet` (souvent "Nom commercial (Raison sociale)"),
`nom_raison_sociale` (dénomination légale nue),
`activite_principale` (code NAF **nu**, ex. "63.11Z" — jamais un objet
{code, libelle}) et `section_activite_principale` (une lettre A-U). L'API ne
renvoie **aucun libellé d'activité détaillé** : `NAF_SECTION_LABELS` fournit
le seul texte officiel disponible, au niveau section (grossier mais stable).
"""

from __future__ import annotations

import os
import time
from dataclasses import asdict, dataclass, field, fields

import requests

from . import config, store
from .normalize import organisation_key

ORG_ENRICHMENT_URL = "https://recherche-entreprises.api.gouv.fr/search"
ORG_ENRICHMENT_RESULTS_PER_QUERY = 5

#: Titres officiels des 21 sections de la nomenclature NAF Rév. 2 (INSEE), et
#: mapping déterministe explicite vers la taxonomie Secteur de Cyberwatch —
#: volontairement une table dédiée à ce texte officiel plutôt qu'un appel à
#: `normalize.classify_sector()` : ce dernier est réglé sur du texte libre
#: d'article et fait déjà correspondre "distribution" à Commerce, ce qui
#: classerait à tort les sections D/E (« Production et distribution
#: d'électricité... ») en Commerce au lieu d'Énergie (constaté à l'exécution
#: du premier benchmark réel). Sans correspondance claire -> Inconnu, jamais
#: une catégorie forcée (mêmes principes que classify_sector). Fixe et
#: grossier (une lettre -> un texte) plutôt qu'une table par code NAF
#: (~700 entrées) : l'API de recherche ne renvoie de toute façon aucun
#: libellé plus précis (cf. docstring de module).
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
    # Politique Immobilier -> Construction/BTP documentée en METHODOLOGY.md §12 :
    # la taxonomie Cyberwatch n'a pas de secteur "Immobilier" dédié.
    "L": ("Activités immobilières", config.SECTOR_CONSTRUCTION),
    # M/N : mêmes activités « de services aux entreprises » que celles déjà
    # regroupées sous SECTOR_SERVICES via ACTIVITY_TO_SECTOR (ransomware.live
    # "business services"/"legal services"/"accounting"...).
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

NAF_SECTION_LABELS: dict[str, str] = {letter: label for letter, (label, _sector) in NAF_SECTIONS.items()}
_LABEL_TO_SECTOR: dict[str, str] = {label: sector for label, sector in NAF_SECTIONS.values()}


def sector_for_activity_label(activity_label: str) -> str:
    """Secteur Cyberwatch déterministe pour un `Activity_Label` (titre de
    section NAF officiel), ou `Inconnu`.

    Ne devine jamais : une section sans correspondance claire (ambiguë ou
    hors taxonomie) renvoie `Inconnu`, jamais une catégorie forcée.
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

#: Version 2 : le matcher accepte aussi les noms commerciaux exacts, toujours
#: sans fuzzy matching. Les anciens NOT_FOUND/AMBIGUOUS doivent donc être
#: retentés ; les MATCHED restent durables mais leur validation Sector est
#: recalculée si nécessaire.
ORG_ENRICHMENT_CACHE_VERSION = "2"

MATCHED = "MATCHED"
AMBIGUOUS = "AMBIGUOUS"
NOT_FOUND = "NOT_FOUND"
ERROR = "ERROR"


class OrgEnrichmentError(Exception):
    """Échec (réseau, HTTP ou format) d'un appel à l'API d'enrichissement."""


@dataclass
class OrgEnrichmentRecord:
    """Une ligne du cache `data/org_enrichment_cache.csv`, clé `Organisation_Key`."""

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
    """État mutable d'un run pour l'enrichissement organisation."""

    enabled: bool = False
    max_calls: int = 200
    cache: dict[str, dict] = field(default_factory=dict)

    calls_attempted: int = 0
    calls_matched: int = 0
    calls_ambiguous: int = 0
    calls_not_found: int = 0
    calls_error: int = 0
    cache_hits: int = 0
    duration_seconds: float = 0.0


def start_state() -> OrgEnrichmentState:
    """Prépare l'état du run et charge le cache existant."""
    state = OrgEnrichmentState(
        enabled=_env_bool("ORG_ENRICHMENT_ENABLED", True),
        max_calls=_env_int("ORG_ENRICHMENT_MAX_CALLS_PER_RUN", 200),
    )
    if not state.enabled:
        return state
    for row in store.load_org_enrichment_cache():
        key = row.get("Organisation_Key", "")
        if not key:
            continue
        if row.get("Cache_Version") != ORG_ENRICHMENT_CACHE_VERSION:
            if row.get("Match_Status") in (NOT_FOUND, AMBIGUOUS):
                continue
            row = dict(row)
            row["Validated_Sector"] = ""
            row["Validated_Via"] = ""
            row["Cache_Version"] = ORG_ENRICHMENT_CACHE_VERSION
        state.cache[key] = row
    return state


def _fetch(query_name: str, state: OrgEnrichmentState) -> dict:
    params = {"q": query_name, "per_page": ORG_ENRICHMENT_RESULTS_PER_QUERY}
    attempt = 0
    while True:
        try:
            response = requests.get(
                ORG_ENRICHMENT_URL, params=params, timeout=ORG_ENRICHMENT_TIMEOUT_SECONDS
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
    commercial_names = candidate.get("noms_commerciaux") or []
    if isinstance(commercial_names, list):
        for value in commercial_names:
            add(value)

    complete = str(candidate.get("nom_complet") or "").strip()
    add(complete)
    if complete.endswith(")") and "(" in complete:
        add(complete.rsplit("(", 1)[0].strip())
    return names


def _match(query_name: str, payload: dict) -> tuple[str, dict]:
    """Match exact raison sociale OU nom commercial, avec SIREN unique."""
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

    distinct_sirens = {str(c.get("siren") or "").strip() for c in exact}
    if "" in distinct_sirens or len(distinct_sirens) > 1:
        return AMBIGUOUS, {}

    return MATCHED, exact[0]


def _record_from_candidate(org_key: str, query_name: str, candidate: dict, fetched_at: str) -> OrgEnrichmentRecord:
    activity_code = str(candidate.get("activite_principale") or "")
    section = str(candidate.get("section_activite_principale") or "")
    activity_label = NAF_SECTION_LABELS.get(section, "")
    headquarters = candidate.get("siege")
    headquarters_department = (
        str(headquarters.get("departement") or "") if isinstance(headquarters, dict) else ""
    )

    matched_name = str(candidate.get("nom_raison_sociale") or candidate.get("nom_complet") or "")
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


def resolve(
    org_key: str, organisation_raw: str, fetched_at: str, state: OrgEnrichmentState
) -> OrgEnrichmentRecord | None:
    """Point d'entrée unique. Ne lève jamais d'exception."""
    if not state.enabled or not org_key or not organisation_raw:
        return None

    cached = state.cache.get(org_key)
    if cached is not None:
        state.cache_hits += 1
        return OrgEnrichmentRecord(**{f.name: cached.get(f.name, "") for f in fields(OrgEnrichmentRecord)})

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
    if status == MATCHED:
        state.calls_matched += 1
        record = _record_from_candidate(org_key, organisation_raw, candidate, fetched_at)
    else:
        if status == AMBIGUOUS:
            state.calls_ambiguous += 1
        else:
            state.calls_not_found += 1
        record = OrgEnrichmentRecord(
            Organisation_Key=org_key,
            Query_Name=organisation_raw,
            Match_Status=status,
            Fetched_At=fetched_at,
            Cache_Version=ORG_ENRICHMENT_CACHE_VERSION,
        )

    state.cache[org_key] = asdict(record)
    return record
