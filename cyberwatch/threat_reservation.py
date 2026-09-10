"""Réserves explicites de menace, portées par la phrase qui les formule.

`normalize.searchable` supprime toute la ponctuation avant l'analyse : les
négations historiques travaillent donc sur un texte sans frontière de phrase et
portent, de fait, sur l'article entier. Ce module procède dans l'ordre inverse —
découpe du texte **brut** en phrases, puis normalisation phrase par phrase — afin
qu'une réserve ne retire que les menaces citées dans la phrase qui la porte.

Conséquence voulue : « Il serait prématuré de parler de ransomware ou de fuite de
données » réserve ces deux menaces, mais une affirmation positive indépendante
située ailleurs dans l'article reste exploitable.
"""

from __future__ import annotations

import json
import re

from . import config
from .normalize import _THREAT_SPECIFIC_PRIORITY, _contains, _matched_threats, searchable

#: Version du vocabulaire de réserve, tracée dans les métadonnées SourceFacts
#: pour qu'une décision archivée reste interprétable après évolution des motifs.
RESERVATION_VERSION = "threat-reservation-2026-09-10.1"

_SENTENCE_RE = re.compile(r"(?<=[.!?;:])\s+|\n+")

#: (code, motif appliqué à la phrase normalisée). Chaque code nomme une
#: formulation réellement observée, jamais une heuristique ouverte.
_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("PREMATURE_TO_NAME", re.compile(
        r"\b(?:premature|premature e|trop tot)\b.{0,20}\bparler\b"
    )),
    ("IMPOSSIBLE_TO_DETERMINE", re.compile(
        r"\bn est (?:donc )?pas possible\b.{0,60}\bdeterminer\b|"
        r"\bimpossible de (?:determiner|etablir|confirmer|savoir)\b|"
        r"\bne permet pas de (?:determiner|etablir|confirmer|savoir)\b"
    )),
    ("NATURE_UNKNOWN", re.compile(
        r"\bnature (?:exacte )?(?:de l attaque|de la cyberattaque|de l incident)\b"
        r".{0,60}\b(?:inconnues?|restent?|non (?:connues?|precisees?))\b|"
        r"\bnature inconnue\b|"
        r"\b(?:restent?|reste) donc inconnues?\b"
    )),
    ("NO_ENTRY_POINT_PUBLISHED", re.compile(
        r"\baucun point d entree\b.{0,40}\brendu public\b|"
        r"\ble point d entree\b.{0,60}\bn a pas ete (?:precise|communique|rendu public)\b"
    )),
    ("NOT_COMMUNICATED", re.compile(
        r"\bn a (?:pas|pour le moment|notamment|non plus|toutefois)\b.{0,40}"
        r"\b(?:communique|precise|fait etat|annonce|detaille)\b|"
        r"\baucune information n a\b.{0,40}\bete communiquee\b"
    )),
    ("PENDING_DETERMINATION", re.compile(
        r"\breste(?:nt)? (?:donc |encore )?(?:a determiner|inconnues?|en cours)\b|"
        r"\ben cours d evaluation\b|\brestent? a determiner\b|"
        r"\bquestions? restent?\b|\breste(?:nt)? (?:encore )?sans reponse\b|"
        r"\bce qui reste a determiner\b"
    )),
    ("HYPOTHETICAL", re.compile(
        r"\beventuel(?:le)?s?\b|"
        r"\brien ne permet\b.{0,40}\baffirmer\b"
    )),
    ("NOT_CONFIRMED", re.compile(
        r"\baucune\b.{0,40}\bconfirmee? a ce stade\b|"
        r"\bnon confirmee?\b|"
        r"\baucune? [a-z ]{0,30}\bconfirmee?\b"
    )),
)


def _sentences(text: str) -> list[str]:
    return [part for part in _SENTENCE_RE.split(str(text or "")) if part.strip()]


def _marker_for(sentence: str) -> str:
    blob = searchable(sentence)
    if not blob:
        return ""
    return next((name for name, rx in _MARKERS if rx.search(blob)), "")


def _reserved_spans(sentences: list[str]) -> list[tuple[int, str]]:
    """Indices de phrases réservées, avec le code du marqueur responsable.

    Une phrase porteuse d'un marqueur et terminée par « : » ouvre une réserve
    sur la liste qui la suit — « La Ville n'a notamment pas précisé : … le point
    d'entrée utilisé ; … si des données ont été exfiltrées. » Sans cette portée,
    chaque puce redeviendrait une affirmation autonome. La liste se reconnaît à
    sa ponctuation française : des éléments en « ; » clos par un « . ».
    """
    spans: list[tuple[int, str]] = []
    index = 0
    while index < len(sentences):
        code = _marker_for(sentences[index])
        if not code:
            index += 1
            continue
        spans.append((index, code))
        cursor = index + 1
        if sentences[index].rstrip().endswith(":") and cursor < len(sentences) \
                and sentences[cursor].rstrip().endswith(";"):
            while cursor < len(sentences) and sentences[cursor].rstrip().endswith(";"):
                spans.append((cursor, code))
                cursor += 1
            if cursor < len(sentences) and sentences[cursor].rstrip().endswith("."):
                spans.append((cursor, code))
                cursor += 1
        index = max(cursor, index + 1)
    return spans


def reserved(*texts: str) -> dict[str, tuple[str, str]]:
    """Menaces réservées, chacune avec ``(code du marqueur, phrase citée)``.

    Une phrase sans marqueur ni portée de liste ne réserve rien : le chemin des
    preuves positives reste intact.
    """
    out: dict[str, tuple[str, str]] = {}
    for text in texts:
        sentences = _sentences(text)
        for position, code in _reserved_spans(sentences):
            sentence = sentences[position]
            for threat in _matched_threats(searchable(sentence)):
                out.setdefault(threat, (code, " ".join(sentence.split())))
    return out


def unreserved_text(*texts: str) -> str:
    """Texte normalisé privé des phrases couvertes par une réserve."""
    kept: list[str] = []
    for text in texts:
        sentences = _sentences(text)
        covered = {position for position, _ in _reserved_spans(sentences)}
        kept.extend(s for i, s in enumerate(sentences) if i not in covered)
    return searchable(" ".join(kept))


#: Termes qui, dans la table historique, rangent un article sous « Intrusion »
#: alors qu'ils ne nomment aucune technique : ils constatent qu'il s'est passé
#: quelque chose, jamais quoi. Un texte qui ne contient que ceux-là n'affirme
#: donc pas une intrusion informatique, et ne peut pas lever une réserve qui
#: porte précisément sur la nature de l'attaque.
_GENERIC_CYBER_TERMS = frozenset({
    "cyberattaque", "cyber attaque", "attaque informatique",
    "piratage", "piratage informatique", "hacking",
})


def _affirms_intrusion(blob: str) -> bool:
    from . import config

    specific = [
        pattern
        for threat, patterns in config.THREAT_RULES if threat == config.THREAT_INTRUSION
        for pattern in patterns
        if pattern not in _GENERIC_CYBER_TERMS
    ]
    return any(_contains(blob, pattern) for pattern in specific)


def net_reserved(*texts: str) -> set[str]:
    """Menaces réservées qu'aucune phrase non réservée n'affirme par ailleurs.

    C'est la seule forme utilisable pour retirer un candidat : une réserve ne
    doit jamais effacer une affirmation positive indépendante. « Il est trop tôt
    pour parler de ransomware. L'attaquant a chiffré les serveurs et réclame une
    rançon. » reste donc un ransomware.
    """
    marks = set(reserved(*texts))
    if not marks:
        return set()
    rest = unreserved_text(*texts)
    affirmed = _matched_threats(rest)
    if config.THREAT_INTRUSION in affirmed and not _affirms_intrusion(rest):
        affirmed.discard(config.THREAT_INTRUSION)
    return marks - affirmed


def _specific(threats) -> set[str]:
    return {t for t in threats if t in _THREAT_SPECIFIC_PRIORITY}


def decision(*texts: str) -> dict | None:
    """Décision explicite ``Inconnu``, ou ``None`` s'il reste une menace étayée.

    Seules les menaces *spécifiques* comptent. Un marqueur générique — « la
    collectivité confirme la cyberattaque » — établit qu'il s'est passé quelque
    chose, jamais quoi : il ne doit donc pas annuler une réserve portant sur la
    nature technique. C'est exactement le cas du Tampon, où la cyberattaque est
    confirmée alors que ransomware et fuite sont explicitement écartés.
    """
    marks = reserved(*texts)
    net = net_reserved(*texts)
    # L'émission se décide sur les menaces *spécifiques* — un « la cyberattaque
    # est confirmée » ne doit pas annuler une réserve portant sur sa nature —
    # mais la charge utile porte toutes les menaces réservées, génériques
    # comprises : sinon `stabilize_threats` republierait « Intrusion » sur un
    # article qui refuse explicitement de trancher entre rançongiciel,
    # intrusion et autre.
    if not _specific(net) or _specific(_matched_threats(unreserved_text(*texts))):
        return None
    return {
        "value": config.THREAT_UNKNOWN,
        "version": RESERVATION_VERSION,
        "reserved": sorted(net),
        "markers": sorted({marks[t][0] for t in net}),
        "evidence": marks[sorted(net)[0]][1],
    }


def covers(payload: object, threat: str) -> bool:
    """Vrai si la réserve archivée couvre explicitement cette menace."""
    if not isinstance(payload, dict) or not threat:
        return False
    return threat in {str(v) for v in payload.get("reserved") or ()}


def index_source_facts(rows) -> dict[str, dict]:
    """Réserves archivées par ``Item_ID``, relues des métadonnées SourceFacts.

    Une ligne antérieure à ce contrat ne porte pas de décision archivée. Si elle
    conserve le contexte éditorial de l'article, la réserve y est recalculée :
    c'est le seul moyen qu'une reprise applique les mêmes règles aux valeurs
    déterministes, aux valeurs LLM et aux valeurs issues du cache. Sans contexte,
    aucune réserve n'est inventée.
    """
    index: dict[str, dict] = {}
    for row in rows or ():
        item_id = str(row.get("Item_ID") or "").strip()
        if not item_id:
            continue
        try:
            metadata = json.loads(row.get("Source_Metadata_JSON") or "{}")
        except (ValueError, TypeError):
            continue
        if not isinstance(metadata, dict):
            continue
        payload = metadata.get("threat_reservation")
        if not (isinstance(payload, dict) and payload.get("reserved")):
            context = str(metadata.get("editorial_context") or "")
            payload = decision(context) if context else None
        if isinstance(payload, dict) and payload.get("reserved"):
            index[item_id] = payload
    return index
