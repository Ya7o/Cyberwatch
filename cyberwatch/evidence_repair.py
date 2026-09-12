"""Réparation de la **preuve** d'un fait, jamais de sa valeur.

Un champ refusé pour `EVIDENCE_TOO_LONG`, `EVIDENCE_NOT_GROUNDED` ou
`FIELD_VALIDATION_REJECTED` porte souvent une valeur juste accompagnée d'une
mauvaise citation : trop longue, recollée avec « … », ou prise dans une phrase
qui n'énonce pas le fait. Ce module cherche dans l'article un extrait **exact**
qui soutient la valeur déjà proposée.

Il ne réécrit jamais le texte, ne recompose jamais une citation et ne propose
jamais une autre valeur. Il ne décide rien non plus : la citation qu'il rend
repasse par `_normalize`, seul juge de l'acceptation.

Portée volontairement étroite : seul `threat_candidate` dispose d'un prédicat
déterministe capable d'attester qu'une phrase soutient la valeur
(`classify_threat`, celui-là même que le validateur applique déjà). Pour
`summary` et `incident_summary`, aucun prédicat local ne dit qu'une phrase
prouve un résumé rédigé — `headline.summary_role_is_supported` ne contrôle
qu'un rôle et rend `True` par défaut. Les essayer déterministement produisait
des preuves absurdes (« Cette différence est importante. » pour le résumé
Brevo) ; ces champs relèvent du retry extractif, pas d'ici.

Fonction pure : ni réseau, ni clé API, comme `sector_resolution.resolve_item`.
"""
from __future__ import annotations

import re

from . import config, hypothesis_lexicon
from .normalize import classify_threat, searchable
from .sector_activity import victim_is_identifiable
from .source_facts_ai_contract import MAX_EVIDENCE_CHARS

#: Champs réparables déterministement. Voir le docstring du module : la liste
#: est courte parce que le prédicat de soutien doit être exact, pas plausible.
DETERMINISTIC_FIELDS = frozenset({"threat_candidate"})

#: Une phrase qui annonce un risque n'énonce pas un incident.
#: `hypothesis_lexicon.PUBLICATION_RE` ne couvre que « risque de … » ; le run
#: RUN-20260912T164223 a montré la forme nominale (« Le principal risque
#: identifié concerne désormais le phishing ciblé. », GreenGo), qui prouverait
#: sinon « Phishing / fraude » à partir d'un risque futur.
_RISK_FRAMING_RE = re.compile(r"\brisques?\b", re.I)

#: Une phrase disant qu'un fait n'est **pas** établi ne peut pas le prouver.
#: `classify_threat` lit « Fuite de données » dans « … l'existence d'une
#: exfiltration effective ne sont pas précisés publiquement. » (Salt).
_NOT_CONFIRMED_RE = re.compile(
    r"\bn[e']\s*(?:sont|est|a|ont)\s+pas\s+"
    r"(?:encore\s+)?(?:pr[ée]cis[ée]\w*|confirm[ée]\w*|[ée]tabli\w*|connu\w*|d[ée]termin[ée]\w*|communiqu[ée]\w*)\b"
    r"|\b(?:pas|non)\s+(?:encore\s+)?(?:confirm[ée]\w*|[ée]tabli\w*|av[ée]r[ée]\w*)\b"
    r"|\baucune?\s+(?:preuve|confirmation|[ée]l[ée]ment)\b"
    r"|\bexistence\s+ou\s+non\b",
    re.I,
)

_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")
_ELLIPSIS_RE = re.compile(r"\.\.\.|…")
_LIST_PREFIXES = (">", "-", "*", "|", "•")


def _clean(chunk: object) -> str:
    return " ".join(str(chunk or "").split()).strip()


def candidate_sentences(context: str) -> list[tuple[str, bool]]:
    """Extraits citables de l'article, avec leur nature (phrase close ou titre).

    Le découpage se fait ligne par ligne : une citation ne peut jamais enjamber
    un retour ligne, sans quoi titre, chapô et première phrase se recollent en
    un bloc qui tient dans la limite de caractères tout en ne citant aucune
    phrase réelle.

    Les titres sont conservés mais signalés : le run RUN-20260912T164223 montre
    qu'ils portent aussi bien la meilleure preuve (« Une fuite de données
    revendiquée contre Aqualter ») que la pire (« Des tentatives de phishing
    particulièrement crédibles », GreenGo, qui ne décrit aucun incident subi).
    L'appelant les soumet donc à une condition supplémentaire.

    Les items de liste et les lignes de métadonnées sont écartés : ils
    énumèrent souvent ce qui reste inconnu (« l'existence ou non d'une
    exfiltration effective ; », Salt).
    """
    seen: set[str] = set()
    candidates: list[tuple[str, bool]] = []
    haystack = searchable(context or "")
    for line in str(context or "").splitlines():
        stripped = line.lstrip()
        if stripped.startswith(_LIST_PREFIXES):
            continue
        heading = stripped.startswith("#")
        for chunk in _SENTENCE_SPLIT_RE.split(stripped.lstrip("#").strip()):
            sentence = _clean(chunk)
            closed = sentence.endswith((".", "!", "?"))
            if not sentence or (not closed and not heading):
                continue
            if not (30 <= len(sentence) <= MAX_EVIDENCE_CHARS):
                continue
            if _ELLIPSIS_RE.search(sentence) or sentence in seen:
                continue
            # La citation doit rester une sous-chaîne exacte de la source ; le
            # découpage n'a le droit de retirer que des blancs.
            if searchable(sentence) not in haystack:
                continue
            seen.add(sentence)
            candidates.append((sentence, closed))
    return candidates


def _supports_threat(sentence: str, value: str) -> bool:
    """La phrase se relit-elle exactement comme la menace déjà proposée ?

    C'est le prédicat que `_normalize` applique déjà à la citation du modèle ;
    on ne fait que l'essayer sur les autres phrases de l'article.
    """
    if _RISK_FRAMING_RE.search(sentence):
        return False
    return classify_threat(sentence) == value


def repair_evidence(field: str, proposed_value: str, context: str, organisation: str = "") -> str:
    """Meilleure citation exacte soutenant `proposed_value`, ou `""`.

    La valeur n'est jamais modifiée ni réinterprétée. Rien n'est accepté ici :
    l'appelant soumet la citation rendue aux validateurs existants.
    """
    value = _clean(proposed_value)
    if field not in DETERMINISTIC_FIELDS or not value or not context:
        return ""
    if value not in config.THREATS or value == config.THREAT_UNKNOWN:
        return ""

    matches: list[tuple[bool, int, str]] = []
    for sentence, closed in candidate_sentences(context):
        if hypothesis_lexicon.PUBLICATION_RE.search(sentence) or _NOT_CONFIRMED_RE.search(sentence):
            continue
        names_victim = victim_is_identifiable(organisation, sentence)
        # Un titre n'est recevable que s'il rattache l'événement à la victime :
        # sans sujet nommé, il qualifie un phénomène, pas un incident subi.
        if not closed and not names_victim:
            continue
        if not _supports_threat(sentence, value):
            continue
        # Une preuve qui nomme la victime prime ; à égalité, la plus courte est
        # la plus explicite — elle cite le fait sans contexte à relire.
        matches.append((not names_victim, len(sentence), sentence))
    return min(matches)[2] if matches else ""
