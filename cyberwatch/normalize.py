"""Normalisation déterministe et conservatrice des champs Cyberwatch."""
from __future__ import annotations

import datetime as dt
import html
import re
import unicodedata
from urllib.parse import urlsplit

from . import config


def strip_accents(value: str) -> str:
    """Retourne ``value`` sans diacritiques, sans altérer la casse."""
    return "".join(
        char for char in unicodedata.normalize("NFKD", value or "")
        if not unicodedata.combining(char)
    )


def searchable(value: str) -> str:
    """Forme de comparaison stable : HTML décodé, sans accents, en minuscules."""
    value = html.unescape(str(value or ""))
    value = strip_accents(value).lower().replace("’", "'")
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return " ".join(value.split())


def _contains(blob: str, needle: str) -> bool:
    needle = searchable(needle)
    if not needle:
        return False
    return bool(re.search(r"(?<![a-z0-9])" + re.escape(needle) + r"(?![a-z0-9])", blob))


def clean_organisation(value: str) -> str:
    value = html.unescape(str(value or ""))
    value = re.sub(r"<[^>]+>", " ", value)
    value = re.sub(r"\s+", " ", value).strip(" \t\r\n-–—:;,.|")
    return value


def organisation_key(value: str) -> str:
    value = searchable(clean_organisation(value))
    value = re.sub(r"\b(?:sas|sasu|sarl|eurl|sa|ltd|limited|inc|corp|corporation)\b", " ", value)
    return " ".join(value.split())


def _hostname(value: str) -> str:
    try:
        parsed = urlsplit(value if "://" in value else f"https://{value}")
    except ValueError:
        return ""
    host = (parsed.hostname or "").lower().strip(".")
    return host[4:] if host.startswith("www.") else host


def canonical_url(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    try:
        parsed = urlsplit(value if "://" in value else f"https://{value}")
    except ValueError:
        return value
    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    path = re.sub(r"/+", "/", parsed.path or "/")
    if path != "/":
        path = path.rstrip("/")
    return f"https://{host}{path}"


def domain_key(value: str) -> str:
    return _hostname(value)


# --------------------------------------------------------------------------
# Menace (§8)
# --------------------------------------------------------------------------


def _is_ambiguous(pattern: str) -> bool:
    return searchable(pattern) in {"intrusion", "attaque", "compromission", "piratage"}


def _is_physical_context(blob: str) -> bool:
    physical = (
        "cambriolage", "vol avec effraction", "effraction physique", "intrusion physique",
        "domicile", "locaux", "batiment", "bâtiment",
    )
    cyber = (
        "cyber", "informatique", "donnees", "données", "serveur", "compte", "comptes",
        "ransomware", "rancongiciel", "rançongiciel", "malware", "ddos", "phishing",
    )
    return any(_contains(blob, marker) for marker in physical) and not any(
        _contains(blob, marker) for marker in cyber
    )


def _has_cyber_marker(blob: str) -> bool:
    return any(
        _contains(blob, marker)
        for marker in (
            "cyberattaque", "cyber attaque", "attaque informatique", "fuite de donnees",
            "violation de donnees", "data breach", "ransomware", "rancongiciel", "malware",
            "phishing", "hameconnage", "ddos", "compromission de compte", "piratage informatique",
        )
    )


def classify_threat(*texts: str, given: str = "") -> str:
    if given:
        cleaned = given.strip()
        if cleaned in config.THREATS:
            return cleaned
        blob = searchable(cleaned)
        physical = _is_physical_context(blob)
        for threat, patterns in config.THREAT_RULES:
            for pattern in patterns:
                if physical and _is_ambiguous(pattern):
                    continue
                if _contains(blob, pattern):
                    return threat
    for text in texts:
        blob = searchable(text)
        physical = _is_physical_context(blob)
        for threat, patterns in config.THREAT_RULES:
            for pattern in patterns:
                if physical and _is_ambiguous(pattern):
                    continue
                if _contains(blob, pattern):
                    return threat
    return config.THREAT_UNKNOWN


def has_cyber_signal(*texts: str) -> bool:
    """Vrai quand un texte porte un signal cyber suffisamment explicite.

    Sert de garde-fou d'ingestion : un article sans aucun marqueur cyber ne
    doit pas entrer dans la base, même s'il provient d'une source cyber.
    """
    blob = searchable(" ".join(t for t in texts if t))
    if not blob:
        return False

    physical = _is_physical_context(blob)
    for _threat, patterns in config.THREAT_RULES:
        for pattern in patterns:
            if physical and _is_ambiguous(pattern):
                continue
            if _contains(blob, pattern):
                return True
    return _has_cyber_marker(blob)


# --------------------------------------------------------------------------
# Secteur (§9)
# --------------------------------------------------------------------------


def _sector_from_blob(blob: str) -> str:
    """Premier secteur dont un motif apparaît dans le texte donné."""
    if not blob:
        return config.SECTOR_UNKNOWN
    for sector, patterns in config.SECTOR_RULES:
        for pattern in patterns:
            if _contains(blob, pattern):
                return sector
    return config.SECTOR_UNKNOWN


def classify_sector(*texts: str, given: str = "") -> str:
    """Secteur normalisé.

    Priorité du §9 : secteur explicitement fourni par la source, puis règle
    fixe, puis `Inconnu`. Aucune recherche Web improvisée.

    Les textes sont examinés **dans l'ordre, séparément** : le premier qui
    tranche l'emporte. C'est ce qui permet à l'appelant de passer d'abord le
    nom de l'organisation, puis seulement le corps de l'article. Sans cette
    séparation, un article mentionnant « fédération » ferait basculer en
    « Sport » une victime qui n'a rien de sportif.
    """
    if given:
        cleaned = given.strip()
        if cleaned in config.SECTORS:
            return cleaned
        mapped = config.ACTIVITY_TO_SECTOR.get(searchable(cleaned))
        if mapped:
            return mapped
        sector = _sector_from_blob(searchable(cleaned))
        if sector != config.SECTOR_UNKNOWN:
            return sector

    for text in texts:
        sector = _sector_from_blob(searchable(text))
        if sector != config.SECTOR_UNKNOWN:
            return sector
    return config.SECTOR_UNKNOWN


#: Formulations explicites d'activité métier. Le vocabulaire reste fermé :
#: ces déclencheurs décrivent l'activité principale, pas le récit de l'incident.
#: ``leader de`` / ``n°1 de`` sont admis car ils introduisent directement le
#: métier revendiqué sur les pages officielles (ex. location, rénovation).
_ACTIVITY_LEADIN_RE = re.compile(
    r"\b(?:sp[ée]cialis[ée]e?\s+dans|sp[ée]cialiste\s+de|[ée]diteur\s+de|acteur\s+de|"
    r"fournisseur\s+de|fabricant\s+de|distributeur\s+de|enseigne\s+de|"
    r"leader\s+de|n(?:[°ºo]\s*)?1\s+de)"
    r"\s+([^,.;:\n]{3,80})",
    re.I,
)
#: Groupes nominaux auto-descriptifs. Ils sont suffisamment spécifiques pour
#: servir de preuve métier même lorsqu'ils précèdent un acronyme entre
#: parenthèses (ex. « Syndicat Départemental d'Énergie de l'Allier (SDE 03) »).
_ACTIVITY_NOUN_RE = re.compile(
    r"\b(club\s+de\s+football(?:\s+professionnel)?|club\s+sportif|"
    r"[ée]tablissement\s+de\s+sant[ée]|centre\s+de\s+formation|"
    r"organisme\s+public|association\s+sportive|"
    r"syndicat\s+d[ée]partemental\s+d['’]?[ée]nergie|"
    r"salle\s+de\s+r[ée]alit[ée]\s+virtuelle)\b",
    re.I,
)


def extract_activity_description(*texts: str) -> str:
    """Formulation métier explicite (§9/§Sector), jamais le récit de l'incident.

    Vocabulaire de déclencheurs fermé : mieux vaut rater une description réelle
    formulée autrement que promouvoir une phrase d'incident en preuve d'activité.
    Chaîne vide si aucun déclencheur n'est présent — jamais de best-effort.
    """
    for text in texts:
        if not text:
            continue
        for pattern in (_ACTIVITY_LEADIN_RE, _ACTIVITY_NOUN_RE):
            match = pattern.search(text)
            if match:
                return match.group(0).strip()
    return ""


# --------------------------------------------------------------------------
# Localisation (§10)
# --------------------------------------------------------------------------

LOCATION_HINTS: list[tuple[str, list[str]]] = [
    (config.LOC_REUNION, ["saint denis de la reunion", "reunionnais", "reunionnaise"]),
    (config.LOC_MAYOTTE, ["mayotte", "mamoudzou", "mahorais", "mahoraise"]),
    (config.LOC_MAURICE, ["mauritius", "mauricien", "mauricienne", "port louis", "rodrigues"]),
    (config.LOC_MADAGASCAR, ["madagascar", "malgache", "antananarivo", "tananarive"]),
    (config.LOC_SEYCHELLES, ["seychelles", "seychellois", "seychelloise", "victoria mahe"]),
    (config.LOC_COMORES, ["comores", "comorien", "comorienne", "moroni", "anjouan"]),
    (config.LOC_FRANCE, ["france metropolitaine"]),
]

_REUNION_PROPER_NAME_RE = re.compile(r"\b(?:La R[ée]union|LA R[ÉE]UNION)\b")
_REUNION_POSTAL_RE = re.compile(r"\b974\d{2}\b")
_MAYOTTE_POSTAL_RE = re.compile(r"\b976\d{2}\b")
_REUNION_DEPARTMENT_RE = re.compile(r"\bdepartement\s+(?:de\s+)?974\b")
_MAYOTTE_DEPARTMENT_RE = re.compile(r"\bdepartement\s+(?:de\s+)?976\b")


def _location_from_text(*texts: str) -> str:
    raw = " ".join(t for t in texts if t)
    if not raw:
        return config.LOC_INCONNU
    if _REUNION_PROPER_NAME_RE.search(raw):
        return config.LOC_REUNION
    blob = searchable(raw)
    if _REUNION_POSTAL_RE.search(blob) or _REUNION_DEPARTMENT_RE.search(blob):
        return config.LOC_REUNION
    if _MAYOTTE_POSTAL_RE.search(blob) or _MAYOTTE_DEPARTMENT_RE.search(blob):
        return config.LOC_MAYOTTE
    for location, hints in LOCATION_HINTS:
        for hint in hints:
            if _contains(blob, hint):
                return location
    return config.LOC_INCONNU


def classify_location(
    *texts: str,
    given: str = "",
    entity: str = "",
    default: str = "",
) -> str:
    if given:
        cleaned = given.strip()
        if cleaned in config.LOCATIONS:
            return cleaned
        location = _location_from_text(cleaned)
        if location != config.LOC_INCONNU:
            return location
    if entity and entity in config.LOCATIONS:
        return entity
    location = _location_from_text(*texts)
    if location != config.LOC_INCONNU:
        return location
    if default and default in config.LOCATIONS:
        return default
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
    "january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "jun": 6,
    "july": 7, "august": 8, "sep": 9, "sept": 9, "oct": 10, "nov": 11, "dec": 12,
}
_TEXT_DATE_RE = re.compile(r"\b(\d{1,2})\s+([a-z]+)\s+(\d{4})\b")


def parse_date(value) -> str:
    if value is None:
        return ""
    if isinstance(value, dt.datetime):
        return value.date().isoformat()
    if isinstance(value, dt.date):
        return value.isoformat()
    text = str(value).strip()
    if not text:
        return ""
    iso_candidate = text.replace("Z", "+00:00")
    try:
        return dt.datetime.fromisoformat(iso_candidate).date().isoformat()
    except ValueError:
        pass
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z"):
        try:
            return dt.datetime.strptime(text, fmt).date().isoformat()
        except ValueError:
            pass
    blob = searchable(text)
    for pattern, order in _DATE_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        values = dict(zip(order, map(int, match.groups())))
        try:
            return dt.date(values["y"], values["m"], values["d"]).isoformat()
        except ValueError:
            return ""
    match = _TEXT_DATE_RE.search(blob)
    if match:
        day = int(match.group(1))
        month_word = match.group(2)
        year = int(match.group(3))
        month = _FRENCH_MONTHS.get(month_word) or _ENGLISH_MONTHS.get(month_word)
        if month:
            try:
                return dt.date(year, month, day).isoformat()
            except ValueError:
                return ""
    return ""
