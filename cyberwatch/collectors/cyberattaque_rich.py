"""Enrichissement mécanique des articles Cyberattaque.org.

Le collecteur source conserve le corps complet WordPress. Cette couche ajoute dans
``RawEntry.source_metadata`` une représentation multi-faits strictement dérivée du
texte : plusieurs comptages, périmètres/systèmes et chronologie de revendication.
Aucun fait n'est inventé et chaque entrée conserve son extrait de preuve.
"""
from __future__ import annotations

import re

from ..normalize import searchable
from .cyberattaque_org import CyberattaqueOrgCollector

_STATUS_PRIORITY = {"confirmed": 4, "reported": 3, "claimed": 2, "unknown": 1}
_STATUS_PATTERNS = (
    ("confirmed", re.compile(r"\b(?:confirme|confirm[ée]e?s?|reconna[iî]t|reconnu|a\s+reconnu|admet|admis)\b", re.I)),
    ("claimed", re.compile(r"\b(?:revendiqu[ée]e?s?|affirme|affirment|selon\s+(?:le|la|les)\s+(?:pirate|attaquant|groupe)|dit\s+avoir)\b", re.I)),
    ("reported", re.compile(r"\b(?:aurait|auraient|serait|seraient|rapport[ée]e?s?|indique|indiquent|selon)\b", re.I)),
)
_COUNT_RE = re.compile(
    r"(?P<number>\d[\d\s\u202f.,]*\d|\d)\s*"
    r"(?P<scale>millions?|milliers?|mille)?\s*"
    r"(?:de\s+|d['’])?\s*"
    r"(?P<unit>comptes?|personnes?|utilisateurs?|clients?|lignes?|enregistrements?|dossiers?|fichiers?)\b",
    re.I,
)
_UNIT_MAP = {
    "compte": "accounts", "comptes": "accounts",
    "personne": "people", "personnes": "people",
    "utilisateur": "users", "utilisateurs": "users",
    "client": "clients", "clients": "clients",
    "ligne": "records", "lignes": "records",
    "enregistrement": "records", "enregistrements": "records",
    "dossier": "files", "dossiers": "files",
    "fichier": "files", "fichiers": "files",
}
_DATE_RE = re.compile(r"\b(?:le\s+)?(?P<day>\d{1,2})\s+(?P<month>janvier|f[ée]vrier|mars|avril|mai|juin|juillet|ao[uû]t|septembre|octobre|novembre|d[ée]cembre)\s+(?P<year>20\d{2})\b", re.I)
_MONTHS = {"janvier": 1, "fevrier": 2, "mars": 3, "avril": 4, "mai": 5, "juin": 6, "juillet": 7, "aout": 8, "septembre": 9, "octobre": 10, "novembre": 11, "decembre": 12}

# Périmètres métier fréquents. Ils sont détectés uniquement si réellement présents.
_SCOPE_PATTERNS = (
    ("SPDC", re.compile(r"\b(?:Serveur\s+Professionnel\s+de\s+Donn[ée]es\s+Cadastrales|SPDC)\b", re.I), "system"),
    ("données cadastrales", re.compile(r"\bdonn[ée]es\s+cadastrales\b", re.I), "dataset"),
    ("successions vacantes", re.compile(r"\bsuccessions?\s+vacantes?\b", re.I), "dataset"),
    ("données fiscales", re.compile(r"\bdonn[ée]es\s+fiscales\b", re.I), "dataset"),
    ("patrimoine immobilier", re.compile(r"\bpatrimoine\s+immobilier\b", re.I), "dataset"),
    ("données personnelles", re.compile(r"\bdonn[ée]es\s+personnelles\b", re.I), "dataset"),
)


def _sentences(text: str) -> list[str]:
    return [part.strip() for part in re.split(r"(?<=[.!?])\s+|\n+", text or "") if part.strip()]


def _status(sentence: str) -> str:
    for status, pattern in _STATUS_PATTERNS:
        if pattern.search(sentence):
            return status
    return "unknown"


def _number(raw: str, scale: str) -> int | None:
    cleaned = (raw or "").replace("\u202f", "").replace(" ", "").strip()
    scale = searchable(scale or "")
    try:
        if scale.startswith("million"):
            return int(round(float(cleaned.replace(",", ".")) * 1_000_000))
        if scale.startswith("millier") or scale == "mille":
            return int(round(float(cleaned.replace(",", ".")) * 1_000))
        return int(cleaned.replace(".", "").replace(",", ""))
    except ValueError:
        return None


def _date(sentence: str) -> str:
    match = _DATE_RE.search(sentence or "")
    if not match:
        return ""
    month = _MONTHS.get(searchable(match.group("month")))
    if not month:
        return ""
    return f"{int(match.group('year')):04d}-{month:02d}-{int(match.group('day')):02d}"


def _scope(sentence: str) -> str:
    for label, pattern, _kind in _SCOPE_PATTERNS:
        if pattern.search(sentence or ""):
            return label
    return ""


def _extract_counts(sentences: list[str]) -> list[dict]:
    facts: list[dict] = []
    seen: set[tuple[int, str, str, str]] = set()
    for sentence in sentences:
        sentence_status = _status(sentence)
        sentence_scope = _scope(sentence)
        for match in _COUNT_RE.finditer(sentence):
            value = _number(match.group("number"), match.group("scale") or "")
            unit_word = searchable(match.group("unit")).rstrip("s")
            unit = _UNIT_MAP.get(searchable(match.group("unit")), _UNIT_MAP.get(unit_word, ""))
            if value is None or not unit:
                continue
            raw = match.group(0).strip()
            key = (value, unit, sentence_scope, sentence_status)
            if key in seen:
                continue
            seen.add(key)
            facts.append({
                "value": value,
                "unit": unit,
                "raw": raw,
                "status": sentence_status,
                "scope": sentence_scope,
                "date": _date(sentence),
                "evidence": sentence[:420],
            })
    facts.sort(key=lambda fact: (-_STATUS_PRIORITY.get(str(fact.get("status")), 0), -int(fact.get("value") or 0), str(fact.get("scope") or "")))
    return facts


def _extract_scopes(sentences: list[str]) -> tuple[list[dict], list[dict]]:
    systems: list[dict] = []
    datasets: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for sentence in sentences:
        for label, pattern, kind in _SCOPE_PATTERNS:
            if not pattern.search(sentence):
                continue
            key = (kind, searchable(label))
            if key in seen:
                continue
            seen.add(key)
            target = systems if kind == "system" else datasets
            target.append({
                "value": label,
                "status": _status(sentence),
                "date": _date(sentence),
                "evidence": sentence[:420],
            })
    return systems, datasets


def _extract_claims(sentences: list[str], counts: list[dict]) -> list[dict]:
    claims: list[dict] = []
    for count in counts:
        claims.append({
            "kind": "affected_count",
            "value": count["value"],
            "unit": count["unit"],
            "status": count["status"],
            "scope": count.get("scope", ""),
            "date": count.get("date", ""),
            "evidence": count["evidence"],
        })
    # Garder aussi les phrases de confirmation/revendication sans chiffre.
    seen_evidence = {searchable(str(claim.get("evidence") or "")) for claim in claims}
    for sentence in sentences:
        status = _status(sentence)
        if status == "unknown":
            continue
        norm = searchable(sentence)
        if norm in seen_evidence:
            continue
        if not re.search(r"\b(?:attaque|cyberattaque|compromission|fuite|intrusion|piratage|donn[ée]es|victime)\b", sentence, re.I):
            continue
        claims.append({
            "kind": "statement",
            "status": status,
            "scope": _scope(sentence),
            "date": _date(sentence),
            "evidence": sentence[:420],
        })
        seen_evidence.add(norm)
        if len(claims) >= 16:
            break
    return claims


def enrich_entry_metadata(entry) -> None:
    text = "\n".join(part for part in (entry.title, entry.summary, entry.content) if part)
    sentences = _sentences(text)
    counts = _extract_counts(sentences)
    systems, datasets = _extract_scopes(sentences)
    claims = _extract_claims(sentences, counts)
    if not any((counts, systems, datasets, claims)):
        return
    metadata = dict(entry.source_metadata or {})
    metadata["rich_facts"] = {
        "version": "1",
        "affected_counts": counts,
        "claims": claims,
        "affected_systems": systems,
        "affected_datasets": datasets,
    }
    entry.source_metadata = metadata


class CyberattaqueRichCollector(CyberattaqueOrgCollector):
    """Collecteur Cyberattaque.org + conservation multi-faits du corps complet."""

    name = "cyberattaque_org"

    def collect(self, client, spec, window):
        result = super().collect(client, spec, window)
        for entry in result.entries:
            enrich_entry_metadata(entry)
        return result
