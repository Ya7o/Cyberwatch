"""Enrichissement gratuit d'entreprise pour `Sector`, uniquement (§12 METHODOLOGY.md).

Quand le contexte source ne décrit pas l'activité de l'organisation, ce
module interroge l'API publique française `recherche-entreprises.api.gouv.fr`
(gratuite, sans clé) pour obtenir un libellé d'activité officiel — jamais
pour deviner un secteur lui-même, seulement pour fournir au filet de
rattrapage LLM (`ai.py`) une description métier explicite à classifier.

Aucune correspondance floue n'est tentée : un candidat n'est retenu que si
son nom normalisé (`normalize.organisation_key`) est **exactement** égal à
celui recherché. Plusieurs entités légales distinctes partageant ce même nom
normalisé (ex. franchises) donnent `AMBIGUOUS`, jamais un choix arbitraire.

Comme `ai.py::_call_openai`, l'appel HTTP est indépendant de
`cyberwatch/http.py` (`HttpClient`/`Budget`) : la dimension de budget ici est
un nombre d'appels par run, pas du respect de robots.txt ou de politesse
inter-hôtes propre à un collecteur.

Schéma réel vérifié le 2026-08-15 via un run GitHub Actions (le domaine est
hors politique réseau du bac à sable de développement, `probe-org-schema`
dans `bench-qualification.yml`) : chaque résultat porte `siren`,
`nom_complet` (souvent "Nom commercial (Raison sociale)", à éviter pour le
matching), `nom_raison_sociale` (dénomination légale nue, préférée),
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
    hors taxonomie) renvoie `Inconnu`, jamais un appel LLM ni une catégorie
    forcée — cohérent avec la politique générale du pipeline Secteur.
    """
    return _LABEL_TO_SECTOR.get(activity_label, config.SECTOR_UNKNOWN)


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
    Evidence_Source: str = "recherche-entreprises.api.gouv.fr"
    Evidence_URL: str = ""
    Match_Status: str = ""
    Fetched_At: str = ""
    #: Secteur Cyberwatch validé pour cette organisation, une fois obtenu
    #: (déterministe ou LLM) — évite toute nouvelle classification tant que
    #: le cache est valide.
    Validated_Sector: str = ""
    #: "" (pas encore tenté) / "deterministic" / "llm" / "llm_declined"
    #: (déjà tenté, jamais concluant : ne jamais retenter à chaque run).
    Validated_Via: str = ""


@dataclass
class OrgEnrichmentState:
    """État mutable d'un run pour l'enrichissement organisation.

    `enabled` vaut `False` par défaut, volontairement à l'opposé de
    `AiRunState.enabled` (qui reflète l'état réel de l'environnement) : sans
    ce défaut sûr, chaque test existant construisant un `AiRunState` avec un
    `Sector` encore `Inconnu` se mettrait à déclencher de vrais appels réseau
    non mockés dès que `ai.qualify_item` escalade vers l'enrichissement.
    Seul `start_state()` (le seul chemin de production réel) l'active.
    """

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
    """Prépare l'état du run : coupe-circuit indépendant de `OPENAI_API_KEY`,
    charge le cache existant."""
    state = OrgEnrichmentState(
        enabled=_env_bool("ORG_ENRICHMENT_ENABLED", True),
        max_calls=_env_int("ORG_ENRICHMENT_MAX_CALLS_PER_RUN", 200),
    )
    if not state.enabled:
        return state
    for row in store.load_org_enrichment_cache():
        key = row.get("Organisation_Key", "")
        if key:
            state.cache[key] = row
    return state


def _fetch(query_name: str, state: OrgEnrichmentState) -> dict:
    """GET unique et indépendant, retry borné sur 429/5xx/timeout.

    Ne retourne jamais autre chose qu'un dict JSON valide ; toute panne
    (réseau, HTTP, JSON) lève `OrgEnrichmentError`, jamais une exception non
    gérée qui remonterait jusqu'à la collecte.
    """
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


def _match(query_name: str, payload: dict) -> tuple[str, dict]:
    """Renvoie (Match_Status, candidat_ou_vide).

    Ne considère que les candidats dont le nom normalisé est **exactement**
    égal à celui recherché — jamais de correspondance floue, jamais le
    premier résultat retourné par l'API.

    `nom_raison_sociale` (dénomination légale nue, ex. "SCALINGO") est
    préféré à `nom_complet` : ce dernier compose souvent la forme
    "Nom commercial (Raison sociale)" (vérifié sur une réponse réelle de
    l'API, ex. "SCALINGO (SCALINGO)"), dont la parenthèse ferait échouer
    l'égalité de clé normalisée même pour une correspondance évidente.
    """
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
        name = candidate.get("nom_raison_sociale") or candidate.get("nom_complet") or ""
        if organisation_key(str(name)) == query_key:
            exact.append(candidate)

    if not exact:
        return NOT_FOUND, {}

    distinct_sirens = {str(c.get("siren") or "") for c in exact}
    if len(distinct_sirens) > 1:
        return AMBIGUOUS, {}

    return MATCHED, exact[0]


def _record_from_candidate(org_key: str, query_name: str, candidate: dict, fetched_at: str) -> OrgEnrichmentRecord:
    # `activite_principale` est un code NAF nu (ex. "63.11Z"), jamais un objet
    # {code, libelle} : l'API de recherche ne renvoie aucun libellé d'activité
    # détaillé (vérifié sur une réponse réelle, cf. commentaire de tête de
    # module). Le seul texte officiel disponible est le titre de la section
    # NAF (une lettre, `section_activite_principale`) via NAF_SECTION_LABELS —
    # volontairement grossier : 21 entrées fixes, jamais une table par code.
    activity_code = str(candidate.get("activite_principale") or "")
    section = str(candidate.get("section_activite_principale") or "")
    activity_label = NAF_SECTION_LABELS.get(section, "")

    matched_name = str(candidate.get("nom_raison_sociale") or candidate.get("nom_complet") or "")
    siren = str(candidate.get("siren") or "")
    return OrgEnrichmentRecord(
        Organisation_Key=org_key,
        Query_Name=query_name,
        Matched_Name=matched_name,
        Company_ID=siren,
        Activity_Code=activity_code,
        Activity_Label=activity_label,
        Evidence_URL=(f"{ORG_ENRICHMENT_URL}?q={siren}" if siren else ""),
        Match_Status=MATCHED,
        Fetched_At=fetched_at,
    )


def resolve(
    org_key: str, organisation_raw: str, fetched_at: str, state: OrgEnrichmentState
) -> OrgEnrichmentRecord | None:
    """Point d'entrée unique. Ne lève jamais d'exception.

    `None` signifie « aucune information disponible » (désactivé, clé vide,
    budget épuisé) : l'appelant doit alors laisser `Sector` à `Inconnu`.
    Un enregistrement `AMBIGUOUS`/`NOT_FOUND`/`ERROR` (statut sans
    `Activity_Label`) doit être traité de la même façon par l'appelant.
    """
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
        )

    state.cache[org_key] = asdict(record)
    return record
