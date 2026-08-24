"""Normalisation déterministe : clés, menaces, secteurs, localisations, dates.

Toutes les fonctions de ce module sont pures et sans accès réseau : c'est ce qui
rend le `REPLAY` (§26) et le test de répétabilité (§27) possibles.
"""

from __future__ import annotations

import csv
import datetime as dt
import re
import unicodedata
from pathlib import Path

from . import config

# --------------------------------------------------------------------------
# Clé d'organisation (§7)
# --------------------------------------------------------------------------

#: Formes juridiques retirées uniquement lorsqu'elles sont des mots isolés.
LEGAL_FORMS = {"sas", "sarl", "sa", "eurl"}
INCIDENT_SUFFIXES = {"pirate", "piratee", "pirates", "piratees", "revendique", "revendiquee"}

_DOMAIN_SUFFIX_RE = re.compile(r"\.(?:fr|com|net|org|eu|io|app)$", flags=re.IGNORECASE)

_PUNCT_RE = re.compile(r"[^\w\s]", flags=re.UNICODE)
_SPACES_RE = re.compile(r"\s+")

# --------------------------------------------------------------------------
# Types de données exposées : taxonomie canonique partagée
# --------------------------------------------------------------------------
#
# Référentiel unique de libellés de types de données, utilisé à la fois par
# l'extraction déterministe (collectors/cyberattaque_rich.py) et par la
# consolidation multi-sources (fact_resolution.py). Sans ce partage, deux
# sources peuvent décrire le même type sous deux formulations (ex.
# "adresses e-mail" vs "Adresse email") qui ne se dédupliquent jamais.
DATA_TYPE_CANONICAL_PATTERNS = (
    ("adresses e-mail", re.compile(r"\b(?:adresses?\s+)?e-?mails?|courriels?\b", re.I)),
    ("numéros de téléphone", re.compile(r"\b(?:num[ée]ros?\s+de\s+)?t[ée]l[ée]phones?\b", re.I)),
    ("adresses postales", re.compile(r"\badresses?\s+(?:postales?|physiques?)\b", re.I)),
    ("noms et prénoms", re.compile(r"\bnoms?\b.{0,30}\bpr[ée]noms?\b|\bpr[ée]noms?\b", re.I)),
    ("dates de naissance", re.compile(r"\bdates?\s+de\s+naissance\b", re.I)),
    ("identifiants", re.compile(r"\bidentifiants?(?:\s+de\s+connexion)?\b", re.I)),
    ("mots de passe", re.compile(r"\bmots?\s+de\s+passe|passwords?\b", re.I)),
    ("données bancaires", re.compile(r"\b(?:donn[ée]es?|coordonn[ée]es?)\s+bancaires?|\bIBAN\b|\bRIB\b", re.I)),
    ("données de santé", re.compile(r"\bdonn[ée]es?\s+(?:de\s+sant[ée]|m[ée]dicales?)\b", re.I)),
    ("pièces d'identité", re.compile(r"\b(?:pi[èe]ces?|cartes?)\s+d['’ ]identit[ée]|passeports?\b", re.I)),
    ("données cadastrales", re.compile(r"\bdonn[ée]es\s+cadastrales\b", re.I)),
    ("données fiscales", re.compile(r"\bdonn[ée]es\s+fiscales\b", re.I)),
    ("données RH", re.compile(r"\b(?:donn[ée]es?|documents?)\s+(?:RH|ressources\s+humaines)\b", re.I)),
    ("secrets cloud", re.compile(r"\b(?:secret|cl[ée]|token|credentials?)\s+(?:AWS|Azure|cloud)\b", re.I)),
    ("BIC / SWIFT", re.compile(r"\b(?:BIC|SWIFT)\b", re.I)),
    ("informations de séjour", re.compile(r"\b(?:s[ée]jour|h[ée]bergement)\b", re.I)),
    ("produits réservés", re.compile(r"\b(?:produits?\s+r[ée]serv[ée]s?|r[ée]servations?\s+(?:de|d['’])?produits?)\b", re.I)),
    ("montants", re.compile(r"\b(?:montants?|prix|sommes?)\b", re.I)),
    ("SIREN / SIRET", re.compile(r"\bSIRE[NT]\b", re.I)),
    ("commentaires", re.compile(r"\bcommentaires?\b", re.I)),
    ("métadonnées techniques", re.compile(r"\bm[ée]tadonn[ée]es?\b", re.I)),
    ("informations de commandes", re.compile(r"\b(?:informations?\s+(?:de|d['’])?commandes?|commandes?)\b", re.I)),
    ("données comptables", re.compile(r"\b(?:donn[ée]es?\s+comptables?|comptabilit[ée])\b", re.I)),
    ("facturation", re.compile(r"\bfacturation\b", re.I)),
    ("contrats", re.compile(r"\bcontrats?\b", re.I)),
    ("factures", re.compile(r"\bfactures?\b", re.I)),
    ("documents internes", re.compile(r"\bdocuments?\s+internes?\b", re.I)),
    ("données techniques", re.compile(r"\bdonn[ée]es?\s+techniques?\b", re.I)),
    ("photographies", re.compile(r"\b(?:photographies?|photos?)\b", re.I)),
    ("situation personnelle", re.compile(r"\bsituation\s+personnelle\b", re.I)),
    ("informations administratives", re.compile(r"\b(?:informations?|documents?)\s+administrati(?:ves?|fs?)\b", re.I)),
)


def canonical_data_type(value: str) -> str:
    """Ramène un libellé de type de donnée à sa forme canonique si connue,
    sinon retourne la valeur telle quelle (jamais d'invention)."""
    for canonical, pattern in DATA_TYPE_CANONICAL_PATTERNS:
        if pattern.search(value):
            return canonical
    return value


def strip_accents(text: str) -> str:
    """Décomposition NFKD puis retrait des marques diacritiques."""
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


def _base_organisation_key(raw: str) -> str:
    text = _DOMAIN_SUFFIX_RE.sub("", strip_accents(str(raw or "")).strip()).lower()
    text = _SPACES_RE.sub(" ", _PUNCT_RE.sub(" ", text)).strip()
    tokens = [token for token in text.split() if token and token not in LEGAL_FORMS]
    while tokens and tokens[-1] in INCIDENT_SUFFIXES:
        tokens.pop()
    return re.sub(r"(?<=[a-z])\s+(?=\d)", "", " ".join(tokens))


def load_organisation_aliases(path: Path | None = None) -> dict[str, str]:
    """Charge le référentiel versionné ; tout conflit est une erreur explicite."""
    alias_path = path or Path(__file__).resolve().parents[1] / "data" / "organisation_aliases.csv"
    aliases: dict[str, str] = {}
    with alias_path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            alias = _base_organisation_key(row.get("alias", ""))
            canonical = _base_organisation_key(row.get("canonical", ""))
            if not alias or not canonical:
                raise ValueError(f"Alias organisation incomplet : {row}")
            if alias in aliases and aliases[alias] != canonical:
                raise ValueError(f"Alias organisation conflictuel : {alias}")
            aliases[alias] = canonical
    return aliases


ORGANISATION_ALIASES = load_organisation_aliases()
_ACRONYM_STOPWORDS = {"de", "du", "des", "la", "le", "les", "d", "l", "a", "au", "aux", "pour", "en", "et", "a"}


def organisation_acronym(name: str) -> str:
    """Acronyme exact d'un libellé, sans aucune recherche approximative."""
    words = _base_organisation_key(name).split()
    return "".join(word[0].upper() for word in words if word and word not in _ACRONYM_STOPWORDS)


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
    # Les sources alternent entre une marque et son domaine public
    # ("Booking" / "Booking.com"). Seul un suffixe final est retiré.
    text = _base_organisation_key(raw)
    return ORGANISATION_ALIASES.get(text, text)


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


def _is_physical_context(blob: str) -> bool:
    """Vrai si le texte décrit un cambriolage plutôt qu'un incident cyber."""
    return any(_contains(blob, marker) for marker in config.PHYSICAL_MARKERS)


def _is_ambiguous(pattern: str) -> bool:
    """Vrai si un motif vaut aussi bien pour le physique que pour le cyber."""
    return any(
        pattern.startswith(prefix) for prefix in config.AMBIGUOUS_PREFIXES
    )


def _has_cyber_marker(blob: str) -> bool:
    """Vrai si le texte porte un marqueur cyber discriminant.

    En contexte manifestement physique — cambriolage, effraction — les racines
    ambiguës comme « intrusion » sont écartées : « intrusion nocturne chez un
    commerçant » n'est pas un incident informatique.
    """
    if not blob:
        return False

    prefixes = config.CYBER_PREFIXES
    if _is_physical_context(blob):
        prefixes = [p for p in prefixes if p not in config.AMBIGUOUS_PREFIXES]

    if any(_starts_with(blob, prefix) for prefix in prefixes):
        return True
    return any(_contains(blob, phrase) for phrase in config.CYBER_PHRASES)


# --------------------------------------------------------------------------
# Menace (§8)
# --------------------------------------------------------------------------

# Les catégories spécifiques sont résolues avant Intrusion, qui regroupe des
# termes très génériques (cyberattaque, piratage, hacking...). L'ordre conserve
# les priorités métier historiques à l'exception volontaire de Fuite, désormais
# plus spécifique qu'une intrusion générique.
_THREAT_SPECIFIC_PRIORITY = (
    config.THREAT_RANSOMWARE,
    config.THREAT_DDOS,
    config.THREAT_MALWARE,
    config.THREAT_LEAK,
    config.THREAT_PHISHING,
    config.THREAT_THIRD_PARTY,
)

# Quelques formulations explicites observées dans les titres réels mais absentes
# de la table historique. Elles restent volontairement limitées à la fuite de
# données : aucune heuristique ouverte ni synonymie approximative.
_THREAT_EXTRA_PATTERNS = {
    config.THREAT_LEAK: (
        "donnees volees",
        "donnees exfiltrees",
        "donnees publiees",
        "data leak",
        "fichiers diffuses",
    ),
}

# Négations conservatrices : uniquement des formulations explicites qui ont
# produit des faux positifs réels. Elles sont masquées avant la recherche de
# candidats ; une autre mention positive située ailleurs dans le texte reste
# donc exploitable.
_THREAT_NEGATION_PATTERNS = (
    re.compile(r"\b(?:aucune|aucun|pas de|sans)\s+fuite(?: de donnees)?\b"),
    re.compile(r"\baucune\s+donnee(?:s)?(?: [a-z]+){0,4}\s+exposee(?:s)?\b"),
    re.compile(r"\b(?:aucune|aucun|pas de|sans)\s+compromission\b"),
    re.compile(r"\bcyberattaque\s+non\s+(?:demontree|demontre)\b"),
    re.compile(r"\borigine\s+cyber\s+non\s+(?:demontree|demontre)\b"),
    re.compile(
        r"\baucun\s+element(?: [a-z]+){0,4}\s+"
        r"(?:ne\s+)?(?:demontre|demontrant)\s+une\s+cyberattaque\b"
    ),
)


def _has_threat_negation(blob: str) -> bool:
    return any(pattern.search(blob) for pattern in _THREAT_NEGATION_PATTERNS)


def _without_negated_threat_claims(blob: str) -> str:
    cleaned = blob
    for pattern in _THREAT_NEGATION_PATTERNS:
        cleaned = pattern.sub(" ", cleaned)
    return _SPACES_RE.sub(" ", cleaned).strip()


def _matched_threats(blob: str) -> set[str]:
    matched: set[str] = set()
    for threat, patterns in config.THREAT_RULES:
        if any(_contains(blob, pattern) for pattern in patterns):
            matched.add(threat)
    for threat, patterns in _THREAT_EXTRA_PATTERNS.items():
        if any(_contains(blob, pattern) for pattern in patterns):
            matched.add(threat)
    return matched


def classify_threat(*texts: str, default: str = "") -> str:
    """Menace normalisée selon spécificité, négation et contexte de source.

    Les preuves spécifiques sont évaluées avant les marqueurs génériques
    d'intrusion. Un défaut de source reste le repli : un simple « piratage » ou
    « cyberattaque » ne peut donc plus transformer une source de fuites en
    Intrusion. Le défaut Ransomware est un contrat univoque et fait toujours foi.
    """
    blob = searchable(" ".join(t for t in texts if t))
    if not blob:
        return default or config.THREAT_UNKNOWN

    had_negation = _has_threat_negation(blob)
    evidence = _without_negated_threat_claims(blob)
    matched = _matched_threats(evidence)

    # ransomware.live est la seule source utilisant ce défaut aujourd'hui ;
    # le contrat de la source est plus fort que le vocabulaire de sa description.
    if default == config.THREAT_RANSOMWARE:
        return config.THREAT_RANSOMWARE

    for threat in _THREAT_SPECIFIC_PRIORITY:
        if threat in matched:
            return threat

    # Un défaut de source (notamment Fuite de données) bat uniquement les
    # signaux génériques. Les preuves spécifiques ci-dessus peuvent toujours
    # l'écraser.
    if default:
        return default

    if config.THREAT_INTRUSION in matched:
        return config.THREAT_INTRUSION
    # Si le seul signal cyber restant vient d'une formulation explicitement
    # négative, mieux vaut conserver Inconnu que fabriquer Autre cyber.
    if had_negation and not matched:
        return config.THREAT_UNKNOWN
    if _has_cyber_marker(evidence):
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

    # Le garde-fou du contexte physique s'applique aussi à la taxonomie : sans
    # cela, la règle « intrusion » qualifierait un cambriolage avant même que
    # le contexte ne soit examiné.
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


#: Formulations explicites d'activité métier ("X spécialisée dans Y", "éditeur
#: de Y"...) : capturent la phrase entière (déclencheur inclus), jamais
#: seulement le complément, pour garder la formulation exacte de la source.
_ACTIVITY_LEADIN_RE = re.compile(
    r"\b(?:sp[ée]cialis[ée]e?\s+dans|[ée]diteur\s+de|acteur\s+de|"
    r"fournisseur\s+de|fabricant\s+de|distributeur\s+de|enseigne\s+de)"
    r"\s+([^,.;:\n]{3,80})",
    re.I,
)
#: Groupes nominaux auto-descriptifs : la phrase elle-même est déjà une
#: description d'activité, vocabulaire fermé (même esprit que `LEGAL_FORMS`).
_ACTIVITY_NOUN_RE = re.compile(
    r"\b(club\s+de\s+football(?:\s+professionnel)?|club\s+sportif|"
    r"[ée]tablissement\s+de\s+sant[ée]|centre\s+de\s+formation|"
    r"organisme\s+public|association\s+sportive)\b",
    re.I,
)


def extract_activity_description(*texts: str) -> str:
    """Formulation métier explicite (§9/§Sector), jamais le récit de
    l'incident.

    Vocabulaire de déclencheurs fermé, à l'image de `_UNIT_MAP` de
    `source_facts.py` : mieux vaut rater une description réelle formulée
    autrement que promouvoir une phrase d'incident en preuve d'activité.
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

#: Indices textuels suffisamment spécifiques pour qualifier un territoire.
#: Les mots ambigus pris isolément (``reunion``, ``maurice``, ``francais``,
#: ``paris``...) sont volontairement exclus : mieux vaut conserver Inconnu ou
#: le défaut de la source que fabriquer une localisation.
LOCATION_HINTS: list[tuple[str, list[str]]] = [
    (config.LOC_REUNION, ["saint denis de la reunion", "reunionnais", "reunionnaise"]),
    (config.LOC_MAYOTTE, ["mayotte", "mamoudzou", "mahorais", "mahoraise"]),
    (config.LOC_MAURICE, ["mauritius", "mauricien", "mauricienne", "port louis", "rodrigues"]),
    (config.LOC_MADAGASCAR, ["madagascar", "malgache", "antananarivo", "tananarive"]),
    (config.LOC_SEYCHELLES, ["seychelles", "seychellois", "seychelloise", "victoria mahe"]),
    (config.LOC_COMORES, ["comores", "comorien", "comorienne", "moroni", "anjouan"]),
    (config.LOC_FRANCE, ["france metropolitaine"]),
]

#: Le nom propre garde une majuscule à « Réunion », contrairement à la réunion
#: de travail. Le test reste sensible à la casse pour éviter ce faux positif.
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
    """Localisation normalisée, du signal le plus fort au plus faible.

    1. localisation explicitement structurée par la source (`given`) ;
    2. territoire de l'entité surveillée reconnue (`entity`) ;
    3. indice territorial textuel suffisamment spécifique ;
    4. règle fixe du collecteur (`default`) ;
    5. `Inconnu`.

    L'indice textuel précède volontairement le défaut : une victime décrite
    comme réunionnaise ou mahoraise doit corriger le défaut France d'une source
    nationale. Les marqueurs ambigus ne figurent pas dans ``LOCATION_HINTS``.
    """
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

#: Tournures marquant le début du récit de l'incident. Le nom de l'organisation
#: s'arrête juste avant : « Impact Centre Chrétien frappé par Qilin » désigne
#: l'organisation « Impact Centre Chrétien ».
_INCIDENT_CUTS = [
    " frappe", " frappee", " victime", " touche", " touchee", " pirate",
    " piratee", " vise", " visee", " cible", " ciblee", " paralyse",
    " paralysee", " revendique", " attaque par", " subit", " confirme",
    " annonce", " hit by", " targeted", " claimed by",
]

#: Caractères décoratifs rencontrés en tête de libellé (pastilles de statut,
#: puces, espaces insécables). Retirés avant toute autre normalisation.
_DECORATIVE_RE = re.compile(
    r"[ ​•■-➿️\U0001F000-\U0001FAFF]", flags=re.UNICODE
)

#: Contenu entre parenthèses en fin de libellé : précisions rédactionnelles
#: (« AXYON (EDF, Eiffage, Bouygues…) ») qui ne font pas partie du nom.
_TRAILING_PAREN_RE = re.compile(r"\s*[\(\[][^\)\]]*[\)\]]\s*$")


def clean_organisation(raw: str) -> str:
    """Nettoie un libellé d'organisation sans en altérer l'identité.

    Retire les décorations (pastilles, puces, espaces insécables), les
    précisions entre parenthèses en fin de libellé, et le préfixe `www.` des
    noms de domaine. Le nom lui-même n'est jamais réécrit : aucun rapprochement
    n'est tenté, conformément au §7.
    """
    if not raw:
        return ""
    text = _DECORATIVE_RE.sub(" ", str(raw))
    text = _SPACES_RE.sub(" ", text).strip(" -–—•\t")

    previous = None
    while previous != text:
        previous = text
        text = _TRAILING_PAREN_RE.sub("", text).strip()

    if text.lower().startswith("www."):
        text = text[4:]
    return text.strip(" -–—•\t")


_LEADING_DECORATIVE_RE = re.compile(rf"^(?:{_DECORATIVE_RE.pattern})+")


def leading_decorative_marker(raw: str) -> str:
    """Préfixe décoratif en tête d'un libellé brut (pastille de statut), tel
    qu'il apparaît avant que `clean_organisation` ne le retire.

    Ne donne aucun sens au marqueur : c'est à l'appelant de décider si un
    marqueur brut suffit (§13 METHODOLOGY.md, faits source — jamais de
    statut canonique sans vérification explicite de la légende de couleur).
    """
    match = _LEADING_DECORATIVE_RE.match(str(raw or ""))
    return match.group(0).strip() if match else ""


def _cut_at_incident(text: str) -> str:
    """Tronque un libellé au premier marqueur de récit d'incident."""
    blob = searchable(text)
    cut = None
    for marker in _INCIDENT_CUTS:
        position = blob.find(marker)
        if position > 0 and (cut is None or position < cut):
            cut = position
    if cut is None:
        return text
    # `searchable` conserve les positions à l'exception de la ponctuation, qui
    # devient espace : la troncature reste alignée sur le texte d'origine.
    return text[:cut].strip(" -–—•,;\t")


def organisation_from_title(title: str) -> str:
    """Organisation déduite d'un titre suivant le schéma `Organisation : ...`.

    Renvoie une chaîne vide si le candidat est un mot rédactionnel ou une phrase
    décrivant l'incident plutôt qu'un nom d'organisation — mieux vaut `Inconnu`
    qu'une organisation inventée.
    """
    if not title:
        return ""
    match = _TITLE_ORG_RE.match(title)
    if not match:
        return ""

    candidate = clean_organisation(_cut_at_incident(match.group(1)))
    if not candidate:
        return ""
    if searchable(candidate) in _TITLE_NOISE:
        return ""
    if len(candidate.split()) > 6:
        return ""
    # Un nom d'organisation ne contient pas le vocabulaire de l'incident.
    if _has_cyber_marker(searchable(candidate)):
        return ""
    return candidate


def organisation_from_entry_title(title: str, max_words: int = 12) -> str:
    """Organisation lue directement dans le titre d'une entrée.

    Réservé aux sources qui déclarent nommer leurs entrées d'après
    l'organisation touchée — chronologies de fuites et listes de victimes. La
    règle est portée par la source, jamais devinée à la forme du titre.
    """
    candidate = clean_organisation(_cut_at_incident(title or ""))
    if not candidate:
        return ""
    if len(candidate.split()) > max_words:
        return ""
    if searchable(candidate) in _TITLE_NOISE:
        return ""
    return candidate


_KWEZI_MUNICIPAL_VICTIM_PATTERNS = (
    re.compile(
        r"\b(?P<organisation>mairie\s+de\s+[a-zà-öø-ÿ'’ -]{2,60}?)\s+"
        r"(?:a\s+(?:ete|été)|est)\s+(?:la\s+)?victime\s+d(?:'une\s+|e\s+une\s+)"
        r"(?:cyberattaque|attaque\s+informatique)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:une\s+)?cyberattaque\s+contre\s+(?P<organisation>mairie\s+de\s+"
        r"[a-zà-öø-ÿ'’ -]{2,60}?)(?:[,. ;:]|$)",
        re.IGNORECASE,
    ),
)


def organisation_from_kwezi_incident_text(text: str) -> str:
    """Victime Kwezi seulement, extraite de tournures municipales explicites.

    Cette règle ne généralise pas les groupes nominaux : elle accepte uniquement
    « Mairie de X » lorsque la phrase affirme explicitement une cyberattaque.
    """
    for pattern in _KWEZI_MUNICIPAL_VICTIM_PATTERNS:
        match = pattern.search(text or "")
        if not match:
            continue
        candidate = clean_organisation(match.group("organisation"))
        if candidate and searchable(candidate).startswith("mairie de "):
            return candidate
    return ""


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
