"""Contrats et portes pures du niveau 2 : activité métier prouvée à l'extérieur.

Ce module ne fait aucun appel réseau et n'écrit aucun fichier. Il porte trois
choses : les deux contrats de données, le vocabulaire fermé des résultats, et
**toutes** les portes de vérification — qui doivent rester des fonctions pures
parce qu'elles sont rejouées à la lecture d'une ligne persistée, par
``cyberwatch check`` comme par ``sector_resolution.resolve_item``.

La séparation centrale, exigée par le cahier des charges, est entre découverte
et preuve :

* un provider ne rend que des :class:`ActivityCandidate` — *où regarder*. Il
  n'a aucun pouvoir de décision métier, pas même via un champ de confiance ;
* seule Cyberwatch produit une :class:`VerifiedActivityEvidence`, et seulement
  après avoir téléchargé le contenu et vérifié la citation dedans.

Il n'existe volontairement **pas** de champ ``confidence`` : l'ancien contrat en
portait un, validé par ``0.8 <= confidence <= 1``, qu'aucun composant du projet
ne calculait. Une porte vérifié/non-vérifié dit la même chose sans inviter un
provider à se noter lui-même.

Aucune porte ne regarde le nom de l'organisation pour en déduire un secteur.
Le nom sert uniquement à *vérifier* qu'une page parle bien de la victime.
"""

from __future__ import annotations

import csv
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Mapping

from . import config
from . import sector as sector_policy
from .normalize import LEGAL_FORMS, searchable
from .org_identity import effective_organisation_key

if TYPE_CHECKING:  # pragma: no cover — uniquement pour le typage
    from .model import Item

# ---------------------------------------------------------------------------
# Vocabulaires fermés
# ---------------------------------------------------------------------------

#: Types de source, chacun avec sa méthode de vérification propre.
SOURCE_OFFICIAL_SITE = "official_site"
SOURCE_PUBLIC_REGISTRY = "public_registry"

#: Providers de découverte livrés. Tout autre provider est injecté.
PROVIDER_OWNED_URL = "owned_url"
PROVIDER_REGISTRY = "entreprises_registry"

#: Méthode ayant établi la preuve. Persistée, car c'est elle qui dit *quelle*
#: porte pure rejouer lors d'une relecture du cache.
VERIFY_PROSE_LITERAL = "PROSE_LITERAL_QUOTE"
VERIFY_REGISTRY_STRUCTURED = "REGISTRY_STRUCTURED_RECORD"
VERIFICATION_METHODS = frozenset({VERIFY_PROSE_LITERAL, VERIFY_REGISTRY_STRUCTURED})

#: Origines du contrat BLF (`Source_Metadata_JSON["blf_activity"]["origin"]`).
#: Une seule valeur est ajoutée par le niveau 2 ; les autres préexistent et
#: leur sémantique est inchangée.
ORIGIN_NATIVE = "BLF_NATIVE"
ORIGIN_REUSE = "BLF_ACTIVITY_REUSE"
ORIGIN_CONFLICT = "BLF_ACTIVITY_CONFLICT"
ORIGIN_NO_EVIDENCE = "BLF_NO_ACTIVITY_EVIDENCE"
ORIGIN_EXTERNAL_APPLIED = "BLF_EXTERNAL_ACTIVITY"
ORIGIN_EXTERNAL_NOT_APPLIED = "BLF_NO_EXTERNAL_ACTIVITY_APPLIED"
ORIGINS = frozenset({
    ORIGIN_NATIVE, ORIGIN_REUSE, ORIGIN_CONFLICT, ORIGIN_NO_EVIDENCE,
    ORIGIN_EXTERNAL_APPLIED, ORIGIN_EXTERNAL_NOT_APPLIED,
})

#: Diagnostic détaillé du niveau 2. Jamais lu par `sector_resolution` : c'est
#: précisément pourquoi il est séparé d'`origin`, qui est un contrat publié sur
#: lequel deux fonctions de production branchent.
EXTERNAL_ACTIVITY_VERIFIED = "EXTERNAL_ACTIVITY_VERIFIED"
EXTERNAL_ACTIVITY_SHADOW = "EXTERNAL_ACTIVITY_SHADOW"
EXTERNAL_ACTIVITY_CACHE_HIT = "EXTERNAL_ACTIVITY_CACHE_HIT"
EXTERNAL_DISABLED = "EXTERNAL_DISABLED"
EXTERNAL_OFFLINE = "EXTERNAL_OFFLINE"
EXTERNAL_NOT_ELIGIBLE = "EXTERNAL_NOT_ELIGIBLE"
EXTERNAL_NO_CANDIDATE = "EXTERNAL_NO_CANDIDATE"
EXTERNAL_SOURCE_NOT_AUTHORISED = "EXTERNAL_SOURCE_NOT_AUTHORISED"
EXTERNAL_HOST_NOT_ALLOWED = "EXTERNAL_HOST_NOT_ALLOWED"
EXTERNAL_URL_REJECTED = "EXTERNAL_URL_REJECTED"
EXTERNAL_REDIRECT_REJECTED = "EXTERNAL_REDIRECT_REJECTED"
EXTERNAL_CONTENT_REJECTED = "EXTERNAL_CONTENT_REJECTED"
EXTERNAL_FETCH_FAILED = "EXTERNAL_FETCH_FAILED"
EXTERNAL_ROBOTS_DISALLOW = "EXTERNAL_ROBOTS_DISALLOW"
EXTERNAL_NO_TEXT = "EXTERNAL_NO_TEXT"
EXTERNAL_CHALLENGE_BODY = "EXTERNAL_CHALLENGE_BODY"
EXTERNAL_IDENTITY_NOT_NAMED = "EXTERNAL_IDENTITY_NOT_NAMED"
EXTERNAL_IDENTITY_HOMONYM = "EXTERNAL_IDENTITY_HOMONYM"
EXTERNAL_IDENTITY_UNVERIFIED = "EXTERNAL_IDENTITY_UNVERIFIED"
EXTERNAL_IDENTITY_AMBIGUOUS_REGISTRY = "EXTERNAL_IDENTITY_AMBIGUOUS_REGISTRY"
EXTERNAL_NO_QUOTE = "EXTERNAL_NO_QUOTE"
EXTERNAL_QUOTE_NOT_GROUNDED = "EXTERNAL_QUOTE_NOT_GROUNDED"
EXTERNAL_QUOTE_DESCRIBES_INCIDENT = "EXTERNAL_QUOTE_DESCRIBES_INCIDENT"
EXTERNAL_ACTIVITY_THIRD_PARTY = "EXTERNAL_ACTIVITY_THIRD_PARTY"
EXTERNAL_ACTIVITY_IDENTITY_AMBIGUOUS = "EXTERNAL_ACTIVITY_IDENTITY_AMBIGUOUS"
EXTERNAL_ACTIVITY_NOT_DESCRIBED = "EXTERNAL_ACTIVITY_NOT_DESCRIBED"
EXTERNAL_ACTIVITY_UNSUPPORTED = "EXTERNAL_ACTIVITY_UNSUPPORTED"
EXTERNAL_EVIDENCE_SECTOR_CONFLICT = "EXTERNAL_EVIDENCE_SECTOR_CONFLICT"
EXTERNAL_NAF_NOT_MAPPABLE = "EXTERNAL_NAF_NOT_MAPPABLE"
EXTERNAL_REGISTRY_UNREADABLE = "EXTERNAL_REGISTRY_UNREADABLE"
EXTERNAL_BUDGET_EXHAUSTED = "EXTERNAL_BUDGET_EXHAUSTED"
EXTERNAL_LLM_BUDGET_EXHAUSTED = "EXTERNAL_LLM_BUDGET_EXHAUSTED"
EXTERNAL_ERROR = "EXTERNAL_ERROR"
EXTERNAL_WITHDRAWN = "EXTERNAL_WITHDRAWN"

EXTERNAL_STATUSES = frozenset({
    EXTERNAL_ACTIVITY_VERIFIED, EXTERNAL_ACTIVITY_SHADOW, EXTERNAL_ACTIVITY_CACHE_HIT,
    EXTERNAL_DISABLED, EXTERNAL_OFFLINE, EXTERNAL_NOT_ELIGIBLE, EXTERNAL_NO_CANDIDATE,
    EXTERNAL_SOURCE_NOT_AUTHORISED, EXTERNAL_HOST_NOT_ALLOWED, EXTERNAL_URL_REJECTED,
    EXTERNAL_REDIRECT_REJECTED, EXTERNAL_CONTENT_REJECTED, EXTERNAL_FETCH_FAILED,
    EXTERNAL_ROBOTS_DISALLOW, EXTERNAL_NO_TEXT, EXTERNAL_CHALLENGE_BODY,
    EXTERNAL_IDENTITY_NOT_NAMED, EXTERNAL_IDENTITY_HOMONYM, EXTERNAL_IDENTITY_UNVERIFIED,
    EXTERNAL_IDENTITY_AMBIGUOUS_REGISTRY, EXTERNAL_NO_QUOTE, EXTERNAL_QUOTE_NOT_GROUNDED,
    EXTERNAL_QUOTE_DESCRIBES_INCIDENT, EXTERNAL_ACTIVITY_THIRD_PARTY,
    EXTERNAL_ACTIVITY_IDENTITY_AMBIGUOUS, EXTERNAL_ACTIVITY_NOT_DESCRIBED,
    EXTERNAL_ACTIVITY_UNSUPPORTED, EXTERNAL_EVIDENCE_SECTOR_CONFLICT,
    EXTERNAL_NAF_NOT_MAPPABLE, EXTERNAL_REGISTRY_UNREADABLE, EXTERNAL_BUDGET_EXHAUSTED,
    EXTERNAL_LLM_BUDGET_EXHAUSTED, EXTERNAL_ERROR, EXTERNAL_WITHDRAWN,
})

#: Traduction 1:1 des trois motifs de `source_facts_ai_activity.binding_rejection`
#: vers le vocabulaire du niveau 2. Le préfixe rend ce vocabulaire autonome sans
#: dupliquer la logique, qui reste celle de la primitive partagée.
_BINDING_STATUSES = {
    "ACTIVITY_THIRD_PARTY": EXTERNAL_ACTIVITY_THIRD_PARTY,
    "ACTIVITY_IDENTITY_AMBIGUOUS": EXTERNAL_ACTIVITY_IDENTITY_AMBIGUOUS,
    "ACTIVITY_NOT_DESCRIBED": EXTERNAL_ACTIVITY_NOT_DESCRIBED,
}


# ---------------------------------------------------------------------------
# Contrats de données
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ActivityCandidate:
    """Découverte seule : *où* regarder. Aucune décision métier.

    ``title`` et ``snippet`` sont des informations de découverte et rien de
    plus : ils ne peuvent jamais devenir une citation. Un extrait de moteur de
    recherche n'est pas une preuve — seul le contenu réellement téléchargé
    l'est.
    """

    url: str
    provider: str
    source_type: str
    title: str = ""
    snippet: str = ""
    #: Ordre d'essai croissant, explicite pour rester testable.
    rank: int = 0


@dataclass(frozen=True)
class VerifiedActivityEvidence:
    """Preuve vérifiée, suffisante pour alimenter la chaîne sectorielle existante.

    ``verified_at`` et ``content_hash`` décrivent le téléchargement qui a
    établi la preuve. Ils ne sont **jamais** rafraîchis lors d'une relecture du
    cache : sans cela, deux runs identiques produiraient des faits différents.
    """

    organisation: str
    organisation_key: str
    activity_description: str
    evidence_quote: str
    evidence_url: str
    source_type: str
    provider: str
    verified_at: str
    content_hash: str
    verification_method: str


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SourceType:
    """Contraintes de transport et de vérification propres à un type de source."""

    name: str
    rank: int
    verification_method: str
    #: Vide = tout hôte public. Non vide = liste blanche stricte.
    hosts: frozenset[str]
    require_https: bool
    allowed_content_types: tuple[str, ...]
    max_content_bytes: int


@dataclass(frozen=True)
class Budgets:
    max_orgs: int
    max_candidates: int
    max_requests: int
    max_seconds: float
    timeout_seconds: int
    ttl_days: int
    rejected_ttl_days: int
    unresolved_ttl_days: int


@dataclass(frozen=True)
class SourcePolicy:
    """Sources autorisées à déclencher le niveau 2, et sous quelles limites.

    ``triggering_source_ids`` n'est **pas** le seul verrou : la garde de
    composante de :func:`cyberwatch.blf_org_enrichment.enrich` exige déjà une
    composante exclusivement BONJOURLAFUITE, sans secteur, sans activité et sans
    rubrique exploitable. Élargir le niveau 2 à une autre source demande donc
    d'éditer cette garde *aussi* ; ce champ seul n'y suffit pas.
    """

    triggering_source_ids: frozenset[str]
    enabled_providers: frozenset[str]
    source_types: tuple[SourceType, ...]
    shadow: bool
    quote_llm: bool
    budgets: Budgets
    registry_url: str

    def authorises(self, source_id: str) -> bool:
        return source_id in self.triggering_source_ids

    def source_type(self, name: str) -> SourceType | None:
        return next((item for item in self.source_types if item.name == name), None)

    def provider_rejection(self, provider: str) -> str:
        return "" if provider in self.enabled_providers else EXTERNAL_SOURCE_NOT_AUTHORISED

    def host_rejection(self, source_type: str, host: str) -> str:
        spec = self.source_type(source_type)
        if spec is None:
            return EXTERNAL_SOURCE_NOT_AUTHORISED
        if spec.hosts and (host or "").strip().lower() not in spec.hosts:
            return EXTERNAL_HOST_NOT_ALLOWED
        return ""


_FALSE = {"0", "false", "no", "off"}


def _flag(env: Mapping[str, str], name: str, default: str) -> bool:
    return str(env.get(name, default)).strip().lower() not in _FALSE


def _number(env: Mapping[str, str], name: str, default: float) -> float:
    try:
        return float(str(env.get(name, default)).strip())
    except (TypeError, ValueError):
        return float(default)


def load_policy(env: Mapping[str, str] | None = None) -> SourcePolicy:
    """Policy effective. Une variable illisible retombe sur le défaut prudent."""
    values = env if env is not None else os.environ
    requested = {
        part.strip() for part in str(
            values.get("EXTERNAL_ACTIVITY_SOURCES",
                       f"{PROVIDER_OWNED_URL},{PROVIDER_REGISTRY}")
        ).split(",") if part.strip()
    }
    budgets = Budgets(
        max_orgs=int(_number(values, "EXTERNAL_ACTIVITY_MAX_ORGS_PER_RUN",
                             config.EXTERNAL_ACTIVITY_MAX_ORGS_PER_RUN)),
        max_candidates=int(_number(values, "EXTERNAL_ACTIVITY_MAX_CANDIDATES_PER_ORG",
                                   config.EXTERNAL_ACTIVITY_MAX_CANDIDATES_PER_ORG)),
        max_requests=int(_number(values, "EXTERNAL_ACTIVITY_MAX_REQUESTS",
                                 config.EXTERNAL_ACTIVITY_MAX_REQUESTS)),
        max_seconds=_number(values, "EXTERNAL_ACTIVITY_MAX_SECONDS",
                            config.EXTERNAL_ACTIVITY_MAX_SECONDS),
        timeout_seconds=int(_number(values, "EXTERNAL_ACTIVITY_TIMEOUT_SECONDS",
                                    config.EXTERNAL_ACTIVITY_TIMEOUT_SECONDS)),
        ttl_days=int(_number(values, "EXTERNAL_ACTIVITY_TTL_DAYS",
                             config.EXTERNAL_ACTIVITY_TTL_DAYS)),
        rejected_ttl_days=int(_number(values, "EXTERNAL_ACTIVITY_REJECTED_TTL_DAYS",
                                      config.EXTERNAL_ACTIVITY_REJECTED_TTL_DAYS)),
        unresolved_ttl_days=int(_number(values, "EXTERNAL_ACTIVITY_UNRESOLVED_TTL_DAYS",
                                        config.EXTERNAL_ACTIVITY_UNRESOLVED_TTL_DAYS)),
    )
    max_bytes = int(_number(values, "EXTERNAL_ACTIVITY_MAX_CONTENT_BYTES",
                            config.EXTERNAL_ACTIVITY_MAX_CONTENT_BYTES))
    return SourcePolicy(
        triggering_source_ids=frozenset({"BONJOURLAFUITE"}),
        enabled_providers=frozenset(requested),
        source_types=(
            SourceType(SOURCE_OFFICIAL_SITE, 0, VERIFY_PROSE_LITERAL, frozenset(),
                       False, ("text/html", "application/xhtml+xml", "text/plain"),
                       max_bytes),
            # Le registre est épinglé sur son hôte : changer l'URL de config ne
            # permet pas d'atteindre un autre service.
            SourceType(SOURCE_PUBLIC_REGISTRY, 1, VERIFY_REGISTRY_STRUCTURED,
                       frozenset({config.EXTERNAL_ACTIVITY_REGISTRY_HOST}), True,
                       ("application/json",), min(max_bytes, 256 * 1024)),
        ),
        shadow=_flag(values, "EXTERNAL_ACTIVITY_SHADOW_MODE", "1"),
        quote_llm=_flag(values, "EXTERNAL_ACTIVITY_QUOTE_LLM_ENABLED", "1"),
        budgets=budgets,
        registry_url=str(values.get("EXTERNAL_ACTIVITY_REGISTRY_URL",
                                    config.EXTERNAL_ACTIVITY_REGISTRY_URL)).strip(),
    )


def enabled(env: Mapping[str, str] | None = None) -> bool:
    """Interrupteur maître. Éteint par défaut : le niveau 2 s'active par décision."""
    values = env if env is not None else os.environ
    return str(values.get("BLF_EXTERNAL_ACTIVITY_ENABLED", "0")).strip().lower() not in _FALSE


def shadow_mode(env: Mapping[str, str] | None = None) -> bool:
    values = env if env is not None else os.environ
    return _flag(values, "EXTERNAL_ACTIVITY_SHADOW_MODE", "1")


# ---------------------------------------------------------------------------
# Nomenclature NAF
# ---------------------------------------------------------------------------

NAF_MAPPABLE = "MAPPABLE"
NAF_TAXONOMY = "TAXONOMY"
NAF_BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class NafDivision:
    """Division NAF officielle, avec le verdict déterministe relu à la main.

    ``status`` dit ce que le projet sait faire de ce libellé :

    * ``MAPPABLE`` — ``classify_sector_activity`` en tire ``expected_sector``,
      vérifié ligne par ligne ;
    * ``TAXONOMY`` — le déterministe est muet, le mapper sectoriel existant
      tranche légitimement ;
    * ``BLOCKED`` — soit le verdict déterministe est mesuré FAUX (« Action
      sociale sans hébergement » déclenche sur un mot nié), soit le libellé ne
      dit rien du métier réel (« Activités des sièges sociaux » décrit une
      coquille de holding). Le provider s'abstient.
    """

    division: str
    label: str
    expected_sector: str
    status: str


def _naf_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "naf_divisions.csv"


def load_naf_divisions(path: Path | None = None) -> dict[str, NafDivision]:
    """Charge la nomenclature ; un fichier absent laisse le registre inerte.

    Chargé à l'import, comme ``normalize.ORGANISATION_ALIASES`` : la porte
    structurée doit rester pure et disponible sans réseau, y compris pour
    ``cyberwatch check``.
    """
    target = path or _naf_path()
    if not target.exists():
        return {}
    divisions: dict[str, NafDivision] = {}
    with target.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            code = str(row.get("Division") or "").strip()
            label = str(row.get("Label") or "").strip()
            status = str(row.get("Status") or "").strip()
            if not code or not label or status not in {NAF_MAPPABLE, NAF_TAXONOMY, NAF_BLOCKED}:
                raise ValueError(f"Division NAF invalide : {row}")
            if code in divisions:
                raise ValueError(f"Division NAF en double : {code}")
            divisions[code] = NafDivision(
                code, label, str(row.get("Expected_Sector") or "").strip(), status)
    return divisions


NAF_DIVISIONS: dict[str, NafDivision] = load_naf_divisions()


def naf_division(code: str) -> NafDivision | None:
    """Division d'un code NAF complet (« 49.41A » -> division « 49 »)."""
    digits = re.sub(r"\D", "", str(code or ""))
    return NAF_DIVISIONS.get(digits[:2]) if len(digits) >= 2 else None


# ---------------------------------------------------------------------------
# Identité sur la page : la garde d'homonymie
# ---------------------------------------------------------------------------

#: Formes juridiques postposées absentes de ``normalize.LEGAL_FORMS``, qui ne
#: contient que ``{eurl, sa, sarl, sas}``. Sans ce complément, « Acme SASU »
#: normaliserait vers ``acme sasu`` et serait pris pour un homonyme d'« Acme ».
_NEUTRAL_SUFFIX = frozenset({
    "sasu", "scop", "scic", "sci", "spa", "ag", "gmbh", "ltd", "limited", "llc",
    "inc", "plc", "bv", "nv", "se", "srl", "ab", "oy", "as", "kg", "sca", "snc",
    "gie", "gmbh", "spol", "oyj", "aps", "sagl",
}) | set(LEGAL_FORMS)

#: Vocabulaire grammatical jamais absorbé dans un nom propre, même capitalisé :
#: une majuscule de début de phrase n'est pas un nom.
_GRAMMAR = frozenset({
    "le", "la", "les", "l", "un", "une", "des", "de", "du", "d", "et", "ou",
    "est", "sont", "etait", "a", "au", "aux", "en", "dans", "pour", "par",
    "ce", "cet", "cette", "ces", "son", "sa", "ses", "leur", "leurs",
    "nous", "notre", "nos", "il", "elle", "ils", "elles", "on",
    "the", "of", "and", "is", "are",
})

_WHITESPACE = re.compile(r"\s+")
_ENDS_WITH_PUNCT = re.compile(r"[^\w\s]$", re.UNICODE)
_OPENING = "«\"'“‘([{"


@dataclass(frozen=True)
class _NameToken:
    raw: str
    core: str
    capitalised: bool
    #: Le jeton se termine par une ponctuation : un nom propre ne la traverse pas.
    closes: bool


def _name_tokens(text: str) -> list[_NameToken]:
    tokens: list[_NameToken] = []
    for raw in _WHITESPACE.split(text or ""):
        if not raw:
            continue
        head = raw.lstrip(_OPENING)
        tokens.append(_NameToken(
            raw=raw,
            core=searchable(raw),
            capitalised=bool(head[:1].isupper()),
            closes=bool(_ENDS_WITH_PUNCT.search(raw)),
        ))
    return tokens


#: Un nom propre d'organisation au-delà de quatre jetons n'est plus un nom :
#: c'est une phrase. Borne l'exploration, et la rend bon marché.
_MAX_NAME_TOKENS = 4


def _mentions(tokens: list[_NameToken], target: str) -> tuple[int, int]:
    """Plus courte suite de jetons dont la clé canonique est celle attendue.

    La concordance passe par ``canonical_name_key`` et non par une comparaison
    de chaînes : c'est la fonction d'identité du projet qui doit trancher, elle
    seule sait retirer un suffixe de domaine (« Booking.com » -> ``booking``),
    une forme juridique ou appliquer un alias validé. Une variante au pluriel
    est admise, par parité avec ``sector_activity.organisation_span``.
    """
    for index in range(len(tokens)):
        for length in range(1, _MAX_NAME_TOKENS + 1):
            if index + length > len(tokens):
                break
            window = " ".join(token.raw for token in tokens[index:index + length])
            key = canonical_name_key(window)
            if key and (key == target or key.rstrip("s") == target.rstrip("s")):
                return index, index + length
    return -1, -1


def name_window(organisation: str, evidence: str, *, organisation_key: str = "") -> str:
    """Nom propre complet qui porte la mention de la victime dans la citation.

    Étend la mention à droite puis à gauche tant que le jeton voisin est
    (a) séparé par un simple espace — toute ponctuation arrête l'extension,
    car une apposition n'est pas un nom : « Acme, entreprise spécialisée… »
    parle bien d'Acme —, (b) capitalisé dans le texte d'origine, et (c) hors du
    vocabulaire grammatical fermé.

    C'est le seul endroit du projet qui a besoin du texte **brut** : la
    capitalisation et la ponctuation sont les deux signaux, et ``searchable``
    les détruit tous les deux.
    """
    tokens = _name_tokens(evidence)
    target = (organisation_key or "").strip() or canonical_name_key(organisation)
    if not tokens or not target:
        return ""

    start, end = _mentions(tokens, target)
    if start < 0:
        return ""

    while end < len(tokens) and not tokens[end - 1].closes:
        nxt = tokens[end]
        if not nxt.core or not nxt.capitalised or nxt.core in _GRAMMAR:
            break
        end += 1
    while start > 0:
        previous = tokens[start - 1]
        if previous.closes or not previous.core or not previous.capitalised:
            break
        if previous.core in _GRAMMAR:
            break
        start -= 1
    return " ".join(token.raw for token in tokens[start:end])


def canonical_name_key(name: str) -> str:
    """Clé canonique d'un libellé, formes juridiques postposées retirées.

    La normalisation du projet passe **avant** le retrait des suffixes, jamais
    après : ``_base_organisation_key`` sait retirer un suffixe de domaine
    (« Booking.com » -> ``booking``) et les formes juridiques qu'il connaît
    déjà. Normaliser d'abord avec ``searchable`` détruirait ce travail — le
    point deviendrait un espace et « Booking.com » vaudrait ``booking com``,
    donc un homonyme de lui-même.

    Un libellé réduit à une seule forme juridique ne devient pas la chaîne
    vide : on conserve la clé directe plutôt que de fabriquer une concordance
    avec n'importe quoi.
    """
    direct = effective_organisation_key(name)
    stripped = " ".join(
        token for token in direct.split() if token not in _NEUTRAL_SUFFIX
    )
    if not stripped or stripped == direct:
        return direct
    return effective_organisation_key(stripped) or direct


def identity_rejection(organisation: str, organisation_key: str, evidence: str) -> str:
    """La citation nomme-t-elle bien *cette* organisation, et pas une homonyme ?

    La règle **défère** à ``effective_organisation_key`` : un alias validé, une
    identité territoriale forte ou une décision du registre d'identité résolvent
    l'homonymie au lieu d'être bloqués par elle. Le niveau 2 ne crée jamais
    d'identité — il se contente de refuser ce qu'il ne sait pas rattacher.
    """
    window = name_window(organisation, evidence, organisation_key=organisation_key)
    if not window:
        return EXTERNAL_IDENTITY_NOT_NAMED
    if canonical_name_key(window) != organisation_key:
        return EXTERNAL_IDENTITY_HOMONYM
    return ""


# ---------------------------------------------------------------------------
# Preuve en prose
# ---------------------------------------------------------------------------

def _http_url(value: str) -> bool:
    return str(value or "").strip().lower().startswith(("http://", "https://"))


def evidence_sector_rejection(activity: str, quote: str) -> str:
    """Refuse une citation qui classe vers un autre secteur que l'activité.

    Mesuré : ``classify_sector_activity`` lit « Transport / Logistique » dans un
    fragment de registre dont le seul mot parlant est la **raison sociale**
    (« TRANSPORTS DUPONT »). Sans cette porte, ``ACTIVITY_EVIDENCE_RULE``
    publierait un secteur déduit du nom de la victime — exactement ce que le
    contrat interdit. Gratuite sur le chemin prose, où la valeur *est* la
    citation et les deux verdicts sont donc identiques par construction.
    """
    from_activity = sector_policy.classify_sector_activity(activity)
    from_quote = sector_policy.classify_sector_activity(quote)
    if from_quote != config.SECTOR_UNKNOWN and from_quote != from_activity:
        return EXTERNAL_EVIDENCE_SECTOR_CONFLICT
    return ""


def verify_prose_evidence(organisation: str, organisation_key: str, activity: str,
                          quote: str, page_text: str) -> str:
    """Portes 10 à 14 du chemin prose. Rend `""` si la preuve est recevable.

    ``page_text`` est le contenu réellement téléchargé lors de la vérification.
    À la relecture d'une ligne de cache on repasse la citation comme son propre
    contexte : l'ancrage littéral a déjà été établi au téléchargement et scellé
    par ``content_hash``. C'est exactement ce que fait déjà
    ``sector_resolution._decision_from_facts`` sur un fait persisté.
    """
    from .sector_activity import (
        _MEMBERSHIP,
        describes_incident,
        names_third_party,
        supported_activity,
    )
    from .source_facts_ai_activity import binding_rejection
    from .source_facts_ai_normalize import _grounded

    if not activity.strip() or not quote.strip():
        return EXTERNAL_NO_QUOTE
    if not _grounded(quote, page_text):
        return EXTERNAL_QUOTE_NOT_GROUNDED
    rejection = identity_rejection(organisation, organisation_key, quote)
    if rejection:
        return rejection
    if describes_incident(quote):
        return EXTERNAL_QUOTE_DESCRIBES_INCIDENT
    if names_third_party(organisation, quote):
        return EXTERNAL_ACTIVITY_THIRD_PARTY
    # Mesuré : « PassPass est une filiale du groupe Widget spécialisé dans la
    # chimie. » passe `supported_activity`, parce que « chimie » figure dans le
    # lexique `_ACTIVITY` et que ce chemin court-circuite le garde
    # d'appartenance — lequel n'est appliqué que par `business_predicate`. Le
    # niveau 2 est plus strict que le contrat partagé, jamais moins : ici, une
    # appartenance à un groupe n'est pas une activité, quel que soit le chemin
    # qui l'a acceptée. Corriger le lexique partagé serait une régression large.
    if _MEMBERSHIP.search(searchable(quote)):
        return EXTERNAL_ACTIVITY_NOT_DESCRIBED
    if not supported_activity(organisation, activity, quote):
        return _BINDING_STATUSES.get(
            binding_rejection(organisation, quote, page_text),
            EXTERNAL_ACTIVITY_UNSUPPORTED,
        )
    return evidence_sector_rejection(activity, quote)


# ---------------------------------------------------------------------------
# Preuve structurée de registre
# ---------------------------------------------------------------------------

#: Valeur du champ ``source`` dans un fragment de preuve structurée. C'est un
#: **format de persistance** : la changer invalide les lignes déjà écrites, qui
#: seront alors refusées à la relecture et repassées en `WITHDRAWN` — sûr, mais
#: à faire délibérément.
REGISTRY_SOURCE = config.EXTERNAL_ACTIVITY_REGISTRY_HOST
REGISTRY_MARKER = f'"source":"{REGISTRY_SOURCE}"'
#: Champs obligatoires du fragment. Leur absence rend la preuve illisible, donc
#: irrecevable : on ne devine jamais un champ manquant.
REGISTRY_REQUIRED_FIELDS = ("nom_complet", "siren", "etat_administratif",
                            "activite_principale", "source")
REGISTRY_ACTIVE = "A"


def structured_proof(evidence: str) -> bool:
    """Discriminant prouvé disjoint de toute prose.

    Exige à la fois un objet JSON et le marqueur de source épinglé. Aucune
    phrase d'article ne peut satisfaire les deux ; un test le vérifie contre
    l'ensemble des citations du corpus existant. C'est ce discriminant qui
    autorise ``sector_activity.supported_activity`` à brancher sans risque.
    """
    text = str(evidence or "").lstrip()
    return text.startswith("{") and REGISTRY_MARKER in text


def _registry_payload(evidence: str) -> dict | None:
    try:
        payload = json.loads(str(evidence or ""))
    except (ValueError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    if any(not str(payload.get(field) or "").strip() for field in REGISTRY_REQUIRED_FIELDS):
        return None
    return payload if str(payload.get("source")) == REGISTRY_SOURCE else None


def structured_activity_supports(organisation: str, value: str, evidence: str) -> bool:
    """Porte structurée, pure et hors ligne, appliquée en lieu et place de la prose.

    Plus stricte que la porte prose, et non moins : elle re-parse le fragment
    téléchargé, revérifie que la raison sociale désigne bien la victime après
    normalisation canonique, que la société est administrativement active, et
    que la valeur d'activité est **exactement** le libellé officiel de la
    division NAF du code cité. Rien n'est déduit, tout est relu.
    """
    payload = _registry_payload(evidence)
    if payload is None or not str(value or "").strip():
        return False
    if str(payload.get("etat_administratif")) != REGISTRY_ACTIVE:
        return False
    if canonical_name_key(str(payload["nom_complet"])) != canonical_name_key(organisation):
        return False
    division = naf_division(str(payload["activite_principale"]))
    if division is None or division.status == NAF_BLOCKED:
        return False
    return division.label == str(value).strip()


def verify_structured_evidence(organisation: str, organisation_key: str, activity: str,
                               quote: str) -> str:
    """Même contrat que :func:`verify_prose_evidence`, motifs précis compris."""
    payload = _registry_payload(quote)
    if not structured_proof(quote) or payload is None:
        return EXTERNAL_REGISTRY_UNREADABLE
    if str(payload.get("etat_administratif")) != REGISTRY_ACTIVE:
        return EXTERNAL_IDENTITY_UNVERIFIED
    if canonical_name_key(str(payload["nom_complet"])) != organisation_key:
        return EXTERNAL_IDENTITY_UNVERIFIED
    division = naf_division(str(payload["activite_principale"]))
    if division is None or division.status == NAF_BLOCKED or division.label != activity.strip():
        return EXTERNAL_NAF_NOT_MAPPABLE
    if not structured_activity_supports(organisation, activity, quote):
        return EXTERNAL_ACTIVITY_UNSUPPORTED
    return evidence_sector_rejection(activity, quote)


# ---------------------------------------------------------------------------
# Re-vérification d'une preuve, et projection vers le contrat BLF
# ---------------------------------------------------------------------------

def accepts(evidence: VerifiedActivityEvidence | None, item: "Item") -> str:
    """Rejoue la porte pure correspondante sur une preuve déjà constituée.

    Appelée par ``blf_org_enrichment`` sur tout résultat de resolver — cache
    compris — afin qu'un durcissement de politique soit **rétroactif** : une
    ligne validée sous une règle plus laxiste est refusée à la relecture.
    """
    if evidence is None:
        return EXTERNAL_NO_CANDIDATE
    key = effective_organisation_key(item.Organisation_Raw, item.Organisation_Key)
    if not key or evidence.organisation_key != key:
        return EXTERNAL_IDENTITY_UNVERIFIED
    if not _http_url(evidence.evidence_url) or not evidence.content_hash.strip():
        return EXTERNAL_URL_REJECTED
    if evidence.verification_method == VERIFY_REGISTRY_STRUCTURED:
        return verify_structured_evidence(
            evidence.organisation, key, evidence.activity_description, evidence.evidence_quote)
    if evidence.verification_method != VERIFY_PROSE_LITERAL:
        return EXTERNAL_ERROR
    return verify_prose_evidence(
        evidence.organisation, key, evidence.activity_description,
        evidence.evidence_quote, evidence.evidence_quote)


def candidate_sector(organisation: str, activity: str, quote: str,
                     source_sector_raw: str = "",
                     call: Callable[[str, str], dict] | None = None) -> tuple[str, str]:
    """Secteur candidat : déterministe d'abord, mapper existant en dernier recours.

    Aucun moteur sectoriel nouveau. ``sector_semantic.map_activity`` est le
    mapper taxonomique déjà en place, avec son cache et son budget ; l'appeler
    ici en mode shadow garantit qu'au basculement en mode actif la passe
    ``annotate_source_facts`` trouvera la même clé de cache et n'émettra
    **aucun** appel supplémentaire.
    """
    from . import sector_semantic

    rule = sector_policy.classify_sector_activity(activity)
    if rule != config.SECTOR_UNKNOWN:
        return rule, "rule"
    proof_rule = sector_policy.classify_sector_activity(quote)
    if proof_rule != config.SECTOR_UNKNOWN:
        return proof_rule, "evidence_rule"
    verdict = sector_semantic.map_activity(
        organisation, activity, quote, source_sector_raw=source_sector_raw, call=call)
    return str(verdict["sector"]), str(verdict["origin"])


def blf_record(evidence: VerifiedActivityEvidence, *, shadow: bool,
               candidate: tuple[str, str] | None = None) -> dict:
    """Record `blf_activity`, appliqué ou seulement consigné.

    En mode shadow, **aucune** clé métier n'apparaît au premier niveau : le
    candidat vit sous ``shadow``. C'est le même procédé que
    ``BLF_NO_ACTIVITY_EVIDENCE`` — un résultat consigné sans être appliqué — et
    c'est ce qui garantit qu'aucun lecteur aval ne peut publier un secteur
    shadow, puisque tous lisent `Activity_Description`, qui reste vide.
    """
    payload = {
        "organisation": evidence.organisation,
        "organisation_key": evidence.organisation_key,
        "activity_description": evidence.activity_description,
        "evidence_quote": evidence.evidence_quote,
        "evidence_url": evidence.evidence_url,
        "source_type": evidence.source_type,
        "provider": evidence.provider,
        "verification_method": evidence.verification_method,
        "content_hash": evidence.content_hash,
        "verified_at": evidence.verified_at,
    }
    if not shadow:
        return {**payload, "origin": ORIGIN_EXTERNAL_APPLIED,
                "external_status": EXTERNAL_ACTIVITY_VERIFIED}
    if candidate is not None:
        payload["candidate_sector"], payload["candidate_sector_origin"] = candidate
    return {"origin": ORIGIN_EXTERNAL_NOT_APPLIED,
            "external_status": EXTERNAL_ACTIVITY_SHADOW, "shadow": payload}


def not_applied(external_status: str) -> dict:
    """Record minimal d'un niveau 2 sans preuve appliquée, motif conservé."""
    return {"origin": ORIGIN_EXTERNAL_NOT_APPLIED,
            "external_status": external_status if external_status in EXTERNAL_STATUSES
            else EXTERNAL_ERROR}
