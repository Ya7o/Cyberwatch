"""Normalisation déterministe : clés, menaces, secteurs, localisations, dates.

Toutes les fonctions de ce module sont pures et sans accès réseau : c'est ce qui
rend le `REPLAY` (§26) et le test de répétabilité (§27) possibles.
"""

from __future__ import annotations

import datetime as dt
import re
import unicodedata

from . import config

# --------------------------------------------------------------------------
# Clé d'organisation (§7)
# --------------------------------------------------------------------------

#: Formes juridiques retirées uniquement lorsqu'elles sont des mots isolés.
LEGAL_FORMS = {"sas", "sarl", "sa", "eurl"}

_PUNCT_RE = re.compile(r"[^\w\s]", flags=re.UNICODE)
_SPACES_RE = re.compile(r"\s+")


def strip_accents(text: str) -> str:
    """Décomposition NFKD puis retrait des marques diacritiques."""
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


def organisation_key(raw: str) -> str:
    """Clé canonique d'une organisation, selon l'ordre imposé au §7.

    NFKD, retrait des accents, minuscules, retrait de la ponctuation,
    espaces multiples réduits, puis retrait des formes juridiques isolées.

    Aucun rapprochement flou n'est effectué : deux libellés qui ne se
    normalisent pas à l'identique restent deux organisations distinctes
    (« un faux doublon est préférable à une fusion non reproductible », §11).
    """
    if not raw:
        return ""
    text = strip_accents(str(raw))
    text = text.lower()
    text = _PUNCT_RE.sub(" ", text)
    text = _SPACES_RE.sub(" ", text).strip()
    if not text:
        return ""
    tokens = [t for t in text.split(" ") if t and t not in LEGAL_FORMS]
    return " ".join(tokens)


def searchable(text: str) -> str:
    """Texte désaccentué, minuscule et sans ponctuation, prêt pour la recherche
    de motifs des tables de menaces et de secteurs."""
    if not text:
        return ""
    out = strip_accents(str(text)).lower()
    out = _PUNCT_RE.sub(" ", out)
    return _SPACES_RE.sub(" ", out).strip()


def _contains(haystack: str, needle: str) -> bool:
    """Test de motif sur limites de mots, pour éviter les faux positifs
    (« port » ne doit pas matcher dans « rapport », « sa » ni dans « santé »)."""
    pattern = r"(?<!\w)" + re.escape(needle.strip()) + r"(?!\w)"
    return re.search(pattern, haystack) is not None


def _starts_with(haystack: str, prefix: str) -> bool:
    """Test de racine en début de mot : « cyber » attrape « cyberattaque »,
    mais pas le « cyber » interne d'un mot sans rapport."""
    pattern = r"(?<!\w)" + re.escape(prefix.strip())
    return re.search(pattern, haystack) is not None


def _has_cyber_marker(blob: str) -> bool:
    """Vrai si le texte porte un marqueur cyber discriminant."""
    if not blob:
        return False
    if any(_starts_with(blob, prefix) for prefix in config.CYBER_PREFIXES):
        return True
    return any(_contains(blob, phrase) for phrase in config.CYBER_PHRASES)


# --------------------------------------------------------------------------
# Menace (§8)
# --------------------------------------------------------------------------


def classify_threat(*texts: str, default: str = "") -> str:
    """Menace normalisée, selon l'ordre de priorité strict du §8.

    Le premier motif rencontré dans l'ordre des règles l'emporte, quelle que
    soit sa position dans le texte : la priorité est celle de la méthode, pas
    celle de la phrase.
    """
    blob = searchable(" ".join(t for t in texts if t))
    if not blob:
        return default or config.THREAT_UNKNOWN

    for threat, patterns in config.THREAT_RULES:
        for pattern in patterns:
            if _contains(blob, pattern):
                return threat

    if default:
        return default
    if _has_cyber_marker(blob):
        return config.THREAT_OTHER
    return config.THREAT_UNKNOWN


def looks_cyber(*texts: str) -> bool:
    """Vrai si le texte relève manifestement du champ cyber.

    Sert de garde-fou d'ingestion : un article sans aucun marqueur cyber ne
    doit pas entrer dans la base, même s'il provient d'une source cyber.
    """
    blob = searchable(" ".join(t for t in texts if t))
    if not blob:
        return False
    for _threat, patterns in config.THREAT_RULES:
        for pattern in patterns:
            if _contains(blob, pattern):
                return True
    return _has_cyber_marker(blob)


# --------------------------------------------------------------------------
# Secteur (§9)
# --------------------------------------------------------------------------


def classify_sector(*texts: str, given: str = "") -> str:
    """Secteur normalisé.

    Priorité du §9 : secteur explicitement fourni par la source, puis règle
    fixe, puis `Inconnu`. Aucune recherche Web improvisée.
    """
    if given:
        cleaned = given.strip()
        if cleaned in config.SECTORS:
            return cleaned
        blob = searchable(cleaned)
        for sector, patterns in config.SECTOR_RULES:
            for pattern in patterns:
                if _contains(blob, pattern):
                    return sector

    blob = searchable(" ".join(t for t in texts if t))
    if not blob:
        return config.SECTOR_UNKNOWN
    for sector, patterns in config.SECTOR_RULES:
        for pattern in patterns:
            if _contains(blob, pattern):
                return sector
    return config.SECTOR_UNKNOWN


# --------------------------------------------------------------------------
# Localisation (§10)
# --------------------------------------------------------------------------

#: Indices textuels par territoire, testés uniquement en dernier recours.
LOCATION_HINTS: list[tuple[str, list[str]]] = [
    (config.LOC_REUNION, ["la reunion", "reunion", "974", "saint denis de la reunion",
                          "reunionnais", "reunionnaise"]),
    (config.LOC_MAYOTTE, ["mayotte", "976", "mamoudzou", "mahorais", "mahoraise"]),
    (config.LOC_MAURICE, ["maurice", "mauritius", "mauricien", "port louis", "rodrigues"]),
    (config.LOC_MADAGASCAR, ["madagascar", "malgache", "antananarivo", "tananarive"]),
    (config.LOC_SEYCHELLES, ["seychelles", "seychellois", "victoria mahe"]),
    (config.LOC_COMORES, ["comores", "comorien", "comorienne", "moroni", "anjouan"]),
    (config.LOC_FRANCE, ["france", "francais", "hexagone", "metropole", "paris"]),
]


def classify_location(
    *texts: str,
    given: str = "",
    default: str = "",
) -> str:
    """Localisation normalisée, selon la priorité du §10.

    1. localisation explicitement structurée par la source (`given`) ;
    2. règle fixe du collecteur (`default`) ;
    3. indice textuel ;
    4. `Inconnu`.

    Un simple mot géographique dans un texte ne suffit jamais à requalifier un
    incident : `given` et `default` priment toujours sur l'indice textuel.
    """
    if given:
        cleaned = given.strip()
        if cleaned in config.LOCATIONS:
            return cleaned
        blob = searchable(cleaned)
        for location, hints in LOCATION_HINTS:
            for hint in hints:
                if _contains(blob, hint):
                    return location

    if default and default in config.LOCATIONS:
        return default

    blob = searchable(" ".join(t for t in texts if t))
    if blob:
        for location, hints in LOCATION_HINTS:
            for hint in hints:
                if _contains(blob, hint):
                    return location

    return config.LOC_INCONNU


# --------------------------------------------------------------------------
# Dates
# --------------------------------------------------------------------------

_DATE_PATTERNS = [
    (re.compile(r"\b(\d{4})-(\d{2})-(\d{2})\b"), ("y", "m", "d")),
    (re.compile(r"\b(\d{2})/(\d{2})/(\d{4})\b"), ("d", "m", "y")),
    (re.compile(r"\b(\d{2})\.(\d{2})\.(\d{4})\b"), ("d", "m", "y")),
]

_FRENCH_MONTHS = {
    "janvier": 1, "fevrier": 2, "mars": 3, "avril": 4, "mai": 5, "juin": 6,
    "juillet": 7, "aout": 8, "septembre": 9, "octobre": 10, "novembre": 11,
    "decembre": 12,
}

_ENGLISH_MONTHS = {
    "january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6,
    "july": 7, "august": 8, "september": 9, "october": 10, "november": 11,
    "december": 12, "jan": 1, "feb": 2, "mar": 3, "apr": 4, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "sept": 9, "oct": 10, "nov": 11, "dec": 12,
}

_TEXT_DATE_RE = re.compile(r"\b(\d{1,2})\s+([a-z]+)\s+(\d{4})\b")


def parse_date(value) -> str:
    """Date normalisée au format `AAAA-MM-JJ`, ou chaîne vide si illisible.

    Accepte les objets date/datetime, l'ISO 8601 (avec ou sans fuseau), les
    formats numériques courants et les dates en toutes lettres françaises et
    anglaises rencontrées dans les flux RSS.
    """
    if value is None:
        return ""
    if isinstance(value, dt.datetime):
        return value.date().isoformat()
    if isinstance(value, dt.date):
        return value.isoformat()

    text = str(value).strip()
    if not text:
        return ""

    # ISO 8601, éventuellement suffixé d'une heure et d'un fuseau.
    iso_candidate = text.replace("Z", "+00:00")
    try:
        return dt.datetime.fromisoformat(iso_candidate).date().isoformat()
    except ValueError:
        pass

    # RFC 822 / 1123, format dominant des flux RSS.
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z",
                "%d %b %Y %H:%M:%S %z", "%a, %d %b %Y"):
        try:
            return dt.datetime.strptime(text, fmt).date().isoformat()
        except ValueError:
            continue

    for pattern, order in _DATE_PATTERNS:
        match = pattern.search(text)
        if match:
            parts = dict(zip(order, match.groups()))
            try:
                return dt.date(
                    int(parts["y"]), int(parts["m"]), int(parts["d"])
                ).isoformat()
            except ValueError:
                continue

    lowered = searchable(text)
    match = _TEXT_DATE_RE.search(lowered)
    if match:
        day, month_name, year = match.groups()
        month = _FRENCH_MONTHS.get(month_name) or _ENGLISH_MONTHS.get(month_name)
        if month:
            try:
                return dt.date(int(year), month, int(day)).isoformat()
            except ValueError:
                return ""
    return ""


def date_or_empty(value: str) -> dt.date | None:
    """Convertit une date normalisée en objet `date`, ou `None`."""
    if not value:
        return None
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        return None


def days_between(earlier: str, later: str) -> int | None:
    """Écart en jours entre deux dates normalisées, ou `None` si indéterminable."""
    start = date_or_empty(earlier)
    end = date_or_empty(later)
    if start is None or end is None:
        return None
    return (end - start).days


# --------------------------------------------------------------------------
# Extraction d'organisation
# --------------------------------------------------------------------------

_TITLE_ORG_RE = re.compile(r"^\s*([^:]{3,80}?)\s*:", flags=re.UNICODE)

#: Préfixes rédactionnels qui ne désignent pas une organisation victime.
_TITLE_NOISE = {
    "alerte", "cyberattaque", "attaque", "info", "breaking", "exclusif",
    "urgent", "securite", "cybersecurite", "fuite de donnees", "ransomware",
    "communique", "edito", "analyse", "enquete", "video", "photos", "direct",
}


def organisation_from_title(title: str) -> str:
    """Organisation déduite d'un titre suivant le schéma `Organisation : ...`.

    Renvoie une chaîne vide si le préfixe est un mot rédactionnel plutôt qu'un
    nom d'organisation — mieux vaut `Inconnu` qu'une organisation inventée.
    """
    if not title:
        return ""
    match = _TITLE_ORG_RE.match(title)
    if not match:
        return ""
    candidate = match.group(1).strip(" -–—•\t")
    if not candidate:
        return ""
    if searchable(candidate) in _TITLE_NOISE:
        return ""
    if len(candidate.split()) > 8:
        return ""
    return candidate


def find_known_entity(text: str, entities: dict[str, str]) -> str:
    """Première entité connue trouvée dans un texte.

    `entities` associe une clé normalisée à son libellé officiel. La recherche
    se fait sur les clés les plus longues d'abord, afin que « Mairie de Saint-Denis »
    l'emporte sur « Saint-Denis ».
    """
    if not text or not entities:
        return ""
    blob = searchable(text)
    for key in sorted(entities, key=len, reverse=True):
        if key and _contains(blob, key):
            return entities[key]
    return ""
