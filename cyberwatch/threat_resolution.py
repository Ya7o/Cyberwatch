"""Résolution explicable de la menace principale d'un incident.

La menace décrit l'événement observé (fuite, intrusion, rançongiciel…), pas
son vecteur d'entrée ni un risque futur mentionné dans un article.  Les faits
structurés priment donc sur les catégories historiques portées par les items.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import json
import re
from typing import Iterable, Mapping

from . import config, threat_reservation
from .model import Item
from .normalize import threat_evidence_text


#: Sources dont le contrat natif *est* la revendication de rançongiciel.
NATIVE_RANSOMWARE_SOURCES = frozenset({"RANSOMWARE_LIVE"})


#: `_best_signal` élit le statut de rang maximal. Sans entrée explicite, un
#: démenti tombait à 0 par défaut — mais aussi toute valeur inconnue du barème.
#: Les statuts négatifs sont donc nommés, sous « » et « unknown ».
_STATUS_RANK = {
    "confirmed": 5,
    "reported": 4,
    "claimed": 3,
    "unknown": 2,
    "": 1,
    "unconfirmed": 1,
    "hypothesis": 1,
    "reserved": 1,
    "denied": 0,
    "negated": 0,
}

_LEAK_RE = re.compile(
    r"\b(?:fuite(?:\s+\w+){0,3}\s+de\s+donnees|data\s+breach|exfiltr\w*|vol\s+de\s+donnees|"
    r"(?:donnees|base|fichiers?|documents?|comptes?)\b.{0,70}\b"
    r"(?:vole\w*|derob\w*|expose\w*|diffus\w*|publie\w*|extrait\w*|mis(?:e)?\s+en\s+vente))\b"
)
_INTRUSION_RE = re.compile(
    r"\b(?:intrusion|piratage|cyberattaque|acces\s+non\s+autorise|"
    r"compromission|site\w*\s+pirate\w*|contenus?\s+modifie\w*|indisponibilite)\b"
)
_PHISHING_RE = re.compile(r"\b(?:phishing|hameconnage|smishing|faux\s+site)\b")
_DDOS_RE = re.compile(r"\b(?:ddos|d\s+dos|deni\s+de\s+service|attaque\s+par\s+saturation)\b")
_MALWARE_RE = re.compile(
    r"\b(?:malware|logiciel\s+malveillant|infostealer|spyware|trojan|cheval\s+de\s+troie)\b"
)
_RANSOMWARE_RE = re.compile(r"\b(?:ransomware|rancongiciel|rancon)\b")


@dataclass(frozen=True)
class ThreatDecision:
    value: str
    status: str
    reason: str
    sources: tuple[str, ...] = ()
    evidence: str = ""
    conflict: bool = False

    def to_payload(self) -> dict[str, object]:
        return {
            "status": self.status or "unknown",
            "reason": self.reason,
            "sources": list(self.sources),
            "evidence": self.evidence,
            "conflict": self.conflict,
        }


def index_source_facts(rows: Iterable[dict] | None) -> dict[str, list[dict]]:
    indexed: dict[str, list[dict]] = defaultdict(list)
    for row in rows or ():
        item_id = str(row.get("Item_ID") or "").strip()
        if item_id:
            indexed[item_id].append(row)
    return dict(indexed)


def _fact_has_leak_evidence(blob: str) -> bool:
    # ``blob`` a déjà été nettoyé des négations et des risques éditoriaux.
    # Relire le résumé brut ici réintroduirait précisément ces faux positifs.
    return bool(_LEAK_RE.search(blob))


def _best_signal(signals: list[tuple[str, str, str]]) -> tuple[str, tuple[str, ...], str]:
    if not signals:
        return "unknown", (), ""
    ordered = sorted(
        signals,
        key=lambda value: (_STATUS_RANK.get(value[0], 0), bool(value[2]), value[1]),
        reverse=True,
    )
    status, source, evidence = ordered[0]
    sources = tuple(sorted({entry[1] for entry in signals if entry[1]}))
    return status or "unknown", sources, evidence


def _legacy_threat_decision(
    ordered: list[Item], item_threats: set[str], reserved: set[str] | None = None,
) -> ThreatDecision:
    # Un repli legacy ne peut pas ressusciter une menace que la source écarte
    # explicitement : c'est par ce chemin que THREAT_SINGLE_LEGACY_VALUE
    # republiait le défaut « Fuite de données » de FrenchBreaches.
    item_threats = item_threats - (reserved or set())
    if len(item_threats) == 1:
        value = next(iter(item_threats))
        return ThreatDecision(value, "unknown", "THREAT_SINGLE_LEGACY_VALUE", conflict=False)
    if item_threats:
        counts = Counter(item.Threat for item in ordered if item.Threat in item_threats)
        top = max(counts.values())
        winners = sorted(value for value, count in counts.items() if count == top)
        if len(winners) == 1:
            return ThreatDecision(winners[0], "unknown", "THREAT_SOURCE_MAJORITY", conflict=True)
        return ThreatDecision(config.THREAT_UNKNOWN, "unknown", "THREAT_CONFLICT", conflict=True)
    return ThreatDecision(config.THREAT_UNKNOWN, "unknown", "THREAT_NO_EVIDENCE")


def _editorial_threat_decision(
    overrides: list[tuple[str, str, str, str]], conflict: bool,
) -> ThreatDecision | None:
    values = {entry[0] for entry in overrides}
    if len(values) != 1:
        return None
    status, sources, evidence = _best_signal([
        (entry[1], entry[2], entry[3]) for entry in overrides
    ])
    return ThreatDecision(
        next(iter(values)), status, "THREAT_EDITORIAL_CORRECTION", sources, evidence, conflict,
    )


def _collect_signals(
    ordered: list[Item], facts_by_item: Mapping[str, list[dict]],
) -> tuple[dict[str, list[tuple[str, str, str]]], list[tuple[str, str, str, str]]]:
    """Relève les signaux de menace des titres puis des faits sourcés.

    Extrait de :func:`resolve_component` pour que la collecte des preuves
    reste lisible séparément de leur arbitrage.
    """
    signals: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    editorial_overrides: list[tuple[str, str, str, str]] = []
    for item in ordered:
        # Threat_Raw peut être un défaut de flux (FrenchBreaches = fuite) et
        # ne constitue donc pas une preuve textuelle. Seul le titre sourcé est
        # relu ici ; la valeur native reste disponible comme repli plus bas.
        item_blob = threat_evidence_text(item.Title)
        source = item.Source_ID
        # `item.Threat` est déjà un produit de `classify_threat` puis de
        # `stabilize_threats` : le relire comme une preuve rendait « reported »
        # une valeur dérivée, avec pour justificatif un titre qui ne dit pas
        # ransomware. Seul le contrat natif d'un leak site subsiste, et il
        # s'annonce pour ce qu'il est : une revendication.
        if source in NATIVE_RANSOMWARE_SOURCES:
            # Le titre du leak site nomme la victime et le groupe
            # (« SAD'S Interim revendiqué par rhysida ») ; `Threat_Raw` ne
            # porte que le défaut littéral « Ransomware ».
            signals[config.THREAT_RANSOMWARE].append(
                ("claimed", source, item.Title or item.Threat_Raw)
            )
        if _RANSOMWARE_RE.search(item_blob):
            signals[config.THREAT_RANSOMWARE].append(("reported", source, item.Title))
        if _DDOS_RE.search(item_blob):
            signals[config.THREAT_DDOS].append(("reported", source, item.Title))
        if _MALWARE_RE.search(item_blob):
            signals[config.THREAT_MALWARE].append(("reported", source, item.Title))
        if _LEAK_RE.search(item_blob):
            signals[config.THREAT_LEAK].append(("reported", source, item.Title))
        if _PHISHING_RE.search(item_blob):
            signals[config.THREAT_PHISHING].append(("reported", source, item.Title))
        if _INTRUSION_RE.search(item_blob):
            signals[config.THREAT_INTRUSION].append(("reported", source, item.Title))

        for row in facts_by_item.get(item.Item_ID, []):
            try:
                metadata = json.loads(str(row.get("Source_Metadata_JSON") or "{}"))
            except (TypeError, ValueError):
                metadata = {}
            override = metadata.get("threat_override") if isinstance(metadata, dict) else None
            if isinstance(override, dict) and override.get("value") in config.THREATS:
                editorial_overrides.append((
                    str(override["value"]),
                    str(override.get("status") or "reported"),
                    source,
                    str(override.get("evidence") or ""),
                ))
            status = str(row.get("Claim_Status") or "reported").strip().lower()
            if status in {"denied", "negated", "hypothesis", "unconfirmed"}:
                continue
            summary = str(row.get("Summary") or "").strip()
            impact = str(row.get("Impact") or "").strip()
            fact_blob = threat_evidence_text(summary, impact)
            evidence = summary or impact or item.Title
            if _RANSOMWARE_RE.search(fact_blob):
                signals[config.THREAT_RANSOMWARE].append((status, source, evidence))
            if _DDOS_RE.search(fact_blob):
                signals[config.THREAT_DDOS].append((status, source, evidence))
            if _MALWARE_RE.search(fact_blob):
                signals[config.THREAT_MALWARE].append((status, source, evidence))
            if _fact_has_leak_evidence(fact_blob):
                signals[config.THREAT_LEAK].append((status, source, evidence))
            if _PHISHING_RE.search(fact_blob):
                signals[config.THREAT_PHISHING].append((status, source, evidence))
            if _INTRUSION_RE.search(fact_blob):
                signals[config.THREAT_INTRUSION].append((status, source, evidence))
            initial_access = str(row.get("Initial_Access") or "").strip()
            if initial_access == "third_party" or str(row.get("Third_Party") or "").strip():
                signals[config.THREAT_THIRD_PARTY].append((status, source, evidence))

    return signals, editorial_overrides


def resolve_component(
    items: Iterable[Item],
    facts_by_item: Mapping[str, list[dict]] | None = None,
) -> ThreatDecision:
    """Choisit la menace principale à partir des preuves de la composante.

    La fuite bat l'intrusion uniquement lorsqu'une exposition/extraction est
    effectivement décrite.  Un simple défaut de source « fuite » ne suffit
    plus.  Phishing n'est retenu que s'il s'agit de l'attaque ou du vecteur,
    jamais d'un risque éditorial en aval.
    """
    ordered = list(items)
    facts_by_item = facts_by_item or {}
    # Les réserves établies à l'extraction voyagent dans les métadonnées
    # SourceFacts. Une menace explicitement écartée par la source ne peut
    # devenir ni un signal, ni un repli legacy, ni la valeur publiée.
    reserved: set[str] = set()
    for rows in facts_by_item.values():
        for payload in threat_reservation.index_source_facts(rows).values():
            reserved.update(str(value) for value in payload.get("reserved") or ())
    # Compromission de compte et tiers compromis décrivent des vecteurs. Ils
    # ne créent pas un conflit avec une menace événementielle documentée.
    non_primary = {config.THREAT_ACCOUNT, config.THREAT_THIRD_PARTY}
    item_threats = {
        item.Threat for item in ordered
        if item.Threat and item.Threat != config.THREAT_UNKNOWN and item.Threat not in non_primary
    }
    conflict = len(item_threats) > 1
    signals: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    editorial_overrides: list[tuple[str, str, str, str]] = []

    signals, editorial_overrides = _collect_signals(ordered, facts_by_item)

    if editorial_overrides:
        decision = _editorial_threat_decision(editorial_overrides, conflict)
        if decision:
            return decision

    # Une menace réservée par la source ne peut plus être élue, quel que soit
    # le statut de son signal.
    for threat in reserved:
        signals.pop(threat, None)

    # Catégories techniques univoques, puis conséquence de fuite prouvée.
    for threat in (
        config.THREAT_RANSOMWARE, config.THREAT_DDOS, config.THREAT_MALWARE,
        config.THREAT_LEAK, config.THREAT_PHISHING, config.THREAT_INTRUSION,
        config.THREAT_THIRD_PARTY,
    ):
        if signals.get(threat):
            status, sources, evidence = _best_signal(signals[threat])
            return ThreatDecision(
                threat, status, f"THREAT_EVIDENCE_{threat.upper().replace(' / ', '_').replace(' ', '_')}",
                sources, evidence, conflict,
            )

    return _legacy_threat_decision(ordered, item_threats, reserved)
