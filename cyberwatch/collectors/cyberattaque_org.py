"""Collecteur WordPress dédié à Cyberattaque.org.

Les articles sont énumérés par :class:`WordPressCollector`. Ce module ne fait
qu'interpréter de façon conservatrice les formulations éditoriales : une
organisation n'est rendue que lorsqu'elle est explicitement reliée à l'incident.
"""
from __future__ import annotations

import re

from .. import status
from ..identity import item_id
from ..model import Item
from ..normalize import clean_organisation, organisation_key, searchable
from .base import RawEntry
from .wordpress import WordPressCollector


_NEGATED_INCIDENTS = (
    "fausse alerte", "ne correspond pas aux donnees", "ne provient pas de",
    "aucune compromission", "aucune intrusion", "revendication dementie",
    "incident dementi",
    "aucune preuve technique ne permet de confirmer",
    "aucune preuve ne permet de confirmer",
    "il ne s agit pas d une fuite confirmee",
)
_OBVIOUS_MULTI = (
    re.compile(r"^\s*\d+\s+SDIS\b", re.I),
    re.compile(r"^\s*Fuite\s+de\s+donn[eé]es\s+scolaires\b", re.I),
    re.compile(r"^\s*Polices\s+municipales\s*:", re.I),
    re.compile(r"^\s*G7\s+d[’'][EÉ]vian\b", re.I),
    re.compile(r"^\s*Son-Video\.com\s*&\s*EasyLounge\b", re.I),
)

# La capture s'arrête à une ponctuation éditoriale : elle ne transforme jamais
# une phrase entière en organisation.
_NAME = r"(?P<organisation>[A-Za-zÀ-ÖØ-öø-ÿ0-9][A-Za-zÀ-ÖØ-öø-ÿ0-9&.'’/ -]{1,78}?)"
_START = r"(?:^|[:.!?]\s+)(?:(?:la|le)\s+|l['’]\s*)?"
_STRONG_AFTER = tuple(re.compile(pattern, re.I) for pattern in (
    rf"\b(?:cyberattaque|attaque(?:\s+informatique)?)\s+(?:contre|visant|chez)\s+{_NAME}(?=[,.;:!]|$)",
    rf"\b(?:intrusion\s+chez|compromission\s+de|piratage\s+de)\s+{_NAME}(?=[,.;:!]|$)",
))
_STRONG_BEFORE = tuple(re.compile(pattern, re.I) for pattern in (
    rf"{_START}{_NAME}\s+(?:a\s+(?:ete|été)\s+)?victime\s+d(?:['’]une?\s+|e\s+\w+\s+)",
    rf"{_START}{_NAME}\s+confirme\s+avoir\s+subi\b",
    rf"{_START}{_NAME}\s+confirme\s+(?:avoir\s+[ée]t[ée]|[êe]tre)\s+victime\b",
    rf"{_START}{_NAME}\s+(?:touch(?:é|ée|e)?|frapp(?:é|ée|e)?|pirat(?:é|ée)|cibl(?:é|ée|e)?|paralys(?:é|ée|e)?)\s+(?:par|après|apres)\b",
    rf"{_START}{_NAME}\s+pirat(?:é|ée)(?=\s*[:,.!]|$)",
    rf"{_START}{_NAME}\s+fait\s+face\s+[àa]\s+(?:une?\s+importante\s+)?"
    r"(?:cyberattaque|attaque\s+(?:informatique|par\s+(?:ransomware|rançongiciel))|"
    r"(?:un\s+)?(?:ransomware|rançongiciel))\b",
))
_FEDERATION_MEMBERS = re.compile(
    r"\b\d[\d\s.,]*\s+membres\s+de\s+la\s+(?P<organisation>"
    r"F[eé]d[eé]ration\s+Fran[cç]aise\s+de\s+[A-Za-zÀ-ÖØ-öø-ÿ'’ -]{2,50}?)\s+"
    r"(?:diffus(?:é|e)s?|expos(?:é|e)s?)\b", re.I,
)
_MUNICIPAL_FACES_ATTACK = re.compile(
    r"\b(?:la\s+)?(?P<organisation>(?:mairie|ville)\s+de\s+"
    r"[A-Za-zÀ-ÖØ-öø-ÿ'’ -]{2,60}?)\s+fait\s+face\s+[àa]\s+"
    r"(?:une?\s+importante\s+)?(?:cyberattaque|attaque\s+(?:informatique|"
    r"par\s+(?:ransomware|rançongiciel))|(?:un\s+)?(?:ransomware|rançongiciel))\b",
    re.I,
)
_PREFIX_EDITORIAL = re.compile(
    r"^(?:cyberattaque|attaque|une?\s+attaque(?:\s+informatique)?|fuite\s+de\s+donnees|une\s+cyberattaque|"
    r"nouvelle\s+cyberattaque|des\s+millions\s+de|les\s+(?:donnees|adresses)\s+de)\b",
    re.I,
)
_PREFIX_COUNT = re.compile(
    r"^\d[\d\s.,]*\s+(?:membres?|lignes?|enregistrements?|comptes?|"
    r"donnees?|dossiers?|sdis)\b", re.I,
)
_LEGACY_EDITORIAL_TAIL = re.compile(
    r"^(.+?)\s+(?:"
    r"annonce\s+(?:avoir\s+)?(?:être|été|etre)\s+victime\b|"
    r"informe(?:\s+ses\s+clients)?\s+d['’]une\s+fuite\b|"
    r"ouvre\s+la\s+s[ée]rie\s+de\s+fuites\b|"
    r"touch(?:é|ée|e)?|victime|cibl(?:é|ée|e)?|frapp(?:é|ée|e)?|"
    r"pirat(?:é|ée)|conteste|alerte|au cœur|sous la menace)\b",
    re.I,
)
_AFTER_COLON_CONFIRMS = re.compile(
    r":\s*(?:l['’]\s*)?(.+?)\s+confirme\s+(?:une?\s+)?cyberattaque\b", re.I,
)


def is_negated_incident(*texts: str) -> bool:
    """Vrai seulement pour un démenti porté par le titre ou l'extrait.

    Le corps peut citer « aucune intrusion » au sujet d'un tiers ou d'une étape
    d'enquête. Sans référence de victime structurée, cette seule occurrence ne
    suffit donc pas à annuler un incident par ailleurs affirmé par le titre.
    """
    title_summary = searchable(" ".join(texts[:2]))
    if any(marker in title_summary for marker in _NEGATED_INCIDENTS):
        return True
    content = searchable(texts[2] if len(texts) > 2 else "")
    return any(marker in content for marker in (
        "fausse alerte", "revendication dementie", "incident dementi",
        "aucune preuve technique ne permet de confirmer",
        "aucune preuve ne permet de confirmer",
        "il ne s agit pas d une fuite confirmee",
    ))


def is_obvious_multi(title: str, summary: str = "", content: str = "") -> bool:
    """Campagnes agrégées qui ne peuvent pas devenir un ITEM unique."""
    if any(pattern.search(title or "") for pattern in _OBVIOUS_MULTI):
        return True
    blob = searchable(" ".join((title, summary, content)))
    if "ville de rennes" in blob and "rennes metropole" in blob:
        return True
    return bool(re.search(r"\b(?:plusieurs|different(?:es|s))\s+ars\b", blob))


def _clean_candidate(value: str) -> str:
    candidate = clean_organisation(value)
    candidate = re.sub(r"^(?:la|le)\s+(?=(?:mairie|ville|federation)\b)", "", candidate, flags=re.I)
    candidate = re.sub(r"^l[’'](?=(?:mairie|ville|federation)\b)", "", candidate, flags=re.I)
    candidate = re.sub(r"^le\s+(?=domaine\s+des\s+tournels\b)", "", candidate, flags=re.I)
    blob = searchable(candidate)
    if blob == "chat control":
        return ""
    if not candidate or len(candidate.split()) > 10:
        return ""
    # Une relation n'autorise pas à prendre une description éditoriale telle que
    # « la plateforme e-campus » ou « son compte BlgCloud » pour une victime.
    # Les formes institutionnelles explicitement admises restent traitées juste
    # après (mairie, ville, fédération).
    if candidate[:1].islower() and not blob.startswith(("mairie ", "ville ", "federation ")):
        return ""
    if _PREFIX_EDITORIAL.match(blob) or _PREFIX_COUNT.match(blob):
        return ""
    if re.search(r"\s(?:annonce|informe|ouvre)\s", blob):
        return ""
    if re.search(
        r"\s(?:confirme|revele|de\s+nouveau|a\s+ete|a\s+ete|"
        r"a\s+confirme|constitue|et\s+l|des\s+donnees)\b", blob,
    ):
        return ""
    if blob.endswith(" est"):
        return ""
    if blob in {
        "un prestataire", "une entreprise", "un site", "la ville", "la mairie",
        "une plateforme", "un service", "un logiciel", "une bibliotheque",
        "un paquet npm", "un compte", "une api", "un outil", "un systeme", "un hebergeur",
    }:
        return ""
    if blob.startswith(("mairie ", "ville ", "federation ")):
        candidate = candidate[:1].upper() + candidate[1:]
    return candidate


def _strong_relation(text: str) -> str:
    for pattern in (*_STRONG_AFTER, *_STRONG_BEFORE, _FEDERATION_MEMBERS, _MUNICIPAL_FACES_ATTACK):
        match = pattern.search(text or "")
        if match:
            candidate = _clean_candidate(match.group("organisation"))
            if candidate:
                return candidate
    return ""


def _safe_prefix(title: str) -> str:
    """Préfixe `Organisation : ...`, après exclusion des accroches narratives."""
    if ":" not in (title or ""):
        return ""
    head = title.split(":", 1)[0].strip()
    if not head:
        return ""
    return _clean_candidate(head)


def organisation_from_cyberattaque_entry(
    entry: RawEntry,
    known_orgs: dict[str, str],
) -> str:
    """Organisation principalement concernée par l'article Cyberattaque.org."""
    texts = (entry.title or "", entry.summary or "", entry.content or "")
    if is_negated_incident(*texts):
        return ""
    if is_obvious_multi(*texts):
        return ""
    # Une confirmation nommée après une accroche est une preuve plus forte que
    # l'accroche elle-même (ex. « ... : l'Armurerie X confirme ... »).
    after_colon = _AFTER_COLON_CONFIRMS.search(entry.title or "")
    if after_colon:
        organisation = _clean_candidate(after_colon.group(1))
        if organisation:
            return organisation
    head = (entry.title or "").split(":", 1)[0].strip()
    legacy = _LEGACY_EDITORIAL_TAIL.match(head)
    if legacy:
        organisation = _clean_candidate(legacy.group(1))
        if organisation:
            return organisation
    # Le titre d'un article est la meilleure indication de son sujet : une
    # relation vers un prestataire dans l'extrait ou le corps ne l'écrase pas.
    organisation = _safe_prefix(entry.title)
    if organisation:
        return organisation
    # Sans organisation fiable dans le titre, les relations explicites servent
    # de fallback, d'abord dans le titre puis dans l'extrait et le corps.
    for position, text in enumerate(texts):
        organisation = _strong_relation(text)
        if organisation:
            # Le corps long mélange souvent la conclusion, les commentaires et
            # des incidents tiers. Pour préserver la précision, il ne suffit à
            # lui seul que pour une collectivité explicitement nommée ou une
            # entité déjà référencée. Le titre et l'extrait restent exploitables
            # pour toute relation forte.
            if position < 2:
                return organisation
            key = searchable(organisation)
            if key in known_orgs or key.startswith(("mairie de ", "ville de ", "federation ")):
                return organisation
    return ""


def organisation_from_title(title: str) -> str:
    """Compatibilité pour l'audit d'anciens items ne contenant que leur titre."""
    return organisation_from_cyberattaque_entry(RawEntry(title=title), {})


def repair_existing_identities(items: list[Item]) -> tuple[list[Item], int]:
    """Répare les titres historiques sans deviner un contexte absent du CSV."""
    repaired: list[Item] = []
    changed = 0
    for item in items:
        organisation = item.Organisation_Raw
        if item.Source_ID == "CYBERATTAQUE_ORG":
            organisation = organisation_from_title(item.Title)
            if not organisation:
                changed += 1
                continue
        key = organisation_key(organisation)
        if organisation == item.Organisation_Raw and key == item.Organisation_Key:
            repaired.append(item)
            continue
        item.Organisation_Raw = organisation
        item.Organisation_Key = key
        item.Item_ID = item_id(item.Source_ID, item.Published_Date, key, item.URL, item.Source_Item_ID)
        repaired.append(item)
        changed += 1
    return repaired, changed


class CyberattaqueOrgCollector(WordPressCollector):
    name = "cyberattaque_org"

    def collect(self, client, spec, window):
        result = super().collect(client, spec, window)
        # Tous les articles de la fenêtre restent disponibles au runner : il est
        # le seul endroit ayant le référentiel et les métriques finales.
        result.status_override = (
            status.OK if result.reason_code == status.REASON_OK else status.FAIL
        )
        result.comment = (
            f"articles_seen={result.items_seen}; "
            f"articles_in_window={result.items_in_window}"
        )
        return result
