"""Dates de l'incident courant, distinctes des rappels d'attaques antérieures."""
from __future__ import annotations

import json
import re

from .model import Item
from .normalize import parse_date, searchable

_HISTORICAL = re.compile(
    r"\b(?:precedent\w* (?:attaque|incident|cyberattaque)|"
    r"(?:attaque|incident|cyberattaque) precedent\w*|"
    r"nouvelle affaire apres|(?:un an|\d+ ans|quelques mois) apres|"
    r"rappel historique)\b"
)
_ATTACK = re.compile(
    r"\b(?:cyberattaque|attaque|intrusion|compromission)\b.{0,100}"
    r"\b(?:a eu lieu|est survenue|a commence|victime)\b|"
    r"\b(?:a ete victime|victime)\b.{0,100}"
    r"\b(?:cyberattaque|attaque|intrusion|compromission)\b"
)
_DISCOVERY = re.compile(r"\b(?:detectee?|decouverte?|notifiee?|informee?|publiee?|revelee?)\b")


def historical_evidence(evidence: str, context: str = "") -> bool:
    """Refuse un rappel explicite, sans rejeter une attaque sur son seul âge."""
    proof = searchable(evidence)
    if _HISTORICAL.search(proof):
        return True
    # La citation riche peut porter du Markdown absent du contexte éditorial.
    body = searchable(context)
    position = body.find(proof) if proof else -1
    if position < 0:
        return False
    prefix = body[max(0, position - 450):position]
    return bool(_HISTORICAL.search(prefix) and re.search(r"\bavait(?: ete)?\b", proof))


def attack_date_from_rich(metadata: dict) -> tuple[str, str]:
    rich = metadata.get("rich_facts") if isinstance(metadata.get("rich_facts"), dict) else {}
    timeline = rich.get("timeline")
    candidates: list[tuple[int, int, str, str]] = []
    for position, row in enumerate(timeline if isinstance(timeline, list) else []):
        if not isinstance(row, dict):
            continue
        date = parse_date(row.get("date"))
        evidence = str(row.get("evidence") or row.get("event") or "").strip()
        blob = searchable(evidence)
        if (not date or not evidence or not _ATTACK.search(blob)
                or historical_evidence(evidence, str(metadata.get("editorial_context") or ""))):
            continue
        score = 2 + 2 * bool(re.search(r"\b(?:a eu lieu|est survenue|a commence)\b", blob))
        if _DISCOVERY.search(blob) and not re.search(r"\b(?:mais|avant d|apres avoir)\b", blob):
            score -= 3
        candidates.append((score, position, date, evidence))
    if not candidates:
        return "", ""
    _, _, date, evidence = sorted(candidates, key=lambda row: (-row[0], row[1]))[0]
    return date, evidence


def sanitize_attack_date(fact: dict, metadata: dict, evidence: dict) -> bool:
    """Conserve le rappel rejeté pour réparer aussi les Event_Date persistées."""
    date = parse_date(fact.get("Attack_Date"))
    proof = str(evidence.get("Attack_Date") or "")
    if date and historical_evidence(proof, str(metadata.get("editorial_context") or "")):
        metadata["rejected_attack_date"] = {
            "value": date, "evidence": proof, "reason": "HISTORICAL_INCIDENT",
        }
        fact["Attack_Date"] = ""
        evidence.pop("Attack_Date", None)
        return True
    if not date:
        date, proof = attack_date_from_rich(metadata)
        if date:
            fact["Attack_Date"] = date
            evidence["Attack_Date"] = proof
            return True
    return False


def apply_event_dates(items: list[Item], facts: list[dict]) -> list[str]:
    """Propage les dates sourcées et retire celles issues d'un rappel rejeté."""
    by_id = {str(row.get("Item_ID") or ""): row for row in facts}
    changed: list[str] = []
    for item in items:
        row = by_id.get(item.Item_ID, {})
        try:
            metadata = json.loads(str(row.get("Source_Metadata_JSON") or "{}"))
        except (TypeError, ValueError):
            metadata = {}
        rejected = metadata.get("rejected_attack_date", {}) if isinstance(metadata, dict) else {}
        previous = item.Event_Date
        if isinstance(rejected, dict) and item.Event_Date == rejected.get("value"):
            item.Event_Date = ""
        date = parse_date(row.get("Attack_Date"))
        if not item.Event_Date and date:
            item.Event_Date = date
        if item.Event_Date != previous:
            changed.append(item.Item_ID)
    return sorted(changed)
