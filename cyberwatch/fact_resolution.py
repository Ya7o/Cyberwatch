"""Résolution canonique des faits incident pour les consommateurs publics.

Les faits bruts restent conservés par source pour l'audit et les analytics. Ce
module produit une vue déterministe, compacte et unique par incident selon la
priorité produit des sources. Le navigateur ne doit pas réimplémenter ces
arbitrages.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any, Callable, Iterable

SOURCE_PRIORITY = (
    "RANSOMWARE_LIVE",
    "CYBERATTAQUE_ORG",
    "FRENCHBREACHES",
    "BONJOURLAFUITE",
    "VEILLE_LLM",
)
_SOURCE_RANK = {source_id: index for index, source_id in enumerate(SOURCE_PRIORITY)}
UNKNOWN_VALUES = {"", "inconnu", "unknown", "n/a", "na", "none", "null", "non etabli", "non établie", "non établi"}
SCALAR_FIELDS = (
    "threat_actor",
    "third_party",
    "initial_access",
    "fine_location",
    "attack_date",
    "discovered_date",
    "impact",
    "evolution",
    "cvss",
    "data_volume",
)
LIST_FIELDS = ("data_types", "vulnerabilities")
RICH_LISTS = ("affected_systems", "affected_datasets")
UNIT_LABELS = {
    "people": "personnes",
    "accounts": "comptes",
    "users": "utilisateurs",
    "clients": "clients",
    "records": "enregistrements",
    "files": "fichiers",
}
STATUS_LABELS = {
    "confirmed": "confirmé",
    "reported": "rapporté",
    "claimed": "revendiqué",
    "unknown": "documenté",
    "unconfirmed": "non confirmé",
    "denied": "démenti",
}


def source_rank(source_id: str | None) -> int:
    """Rang stable d'une source ; une source inconnue vient toujours après."""
    return _SOURCE_RANK.get(str(source_id or "").strip(), len(SOURCE_PRIORITY) + 100)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _norm(value: Any) -> str:
    text = unicodedata.normalize("NFD", _text(value))
    text = "".join(char for char in text if unicodedata.category(char) != "Mn")
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def _known(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return _norm(value) not in UNKNOWN_VALUES


def _ordered_facts(facts: Iterable[dict]) -> list[dict]:
    return sorted(
        (fact for fact in facts if isinstance(fact, dict)),
        key=lambda fact: (source_rank(fact.get("source")), _text(fact.get("source")), _text(fact.get("item_id"))),
    )


def _supporting_sources(facts: Iterable[dict], getter: Callable[[dict], Any], chosen: Any) -> list[str]:
    chosen_norm = _norm(chosen)
    sources: list[str] = []
    for fact in _ordered_facts(facts):
        candidate = getter(fact)
        if _known(candidate) and _norm(candidate) == chosen_norm:
            source = _text(fact.get("source"))
            if source and source not in sources:
                sources.append(source)
    return sources


def resolve_scalar(facts: Iterable[dict], field: str) -> dict | None:
    """Résout un champ scalaire : premier fait non vide selon la priorité."""
    ordered = _ordered_facts(facts)
    for fact in ordered:
        value = fact.get(field)
        if not _known(value):
            continue
        source = _text(fact.get("source"))
        return {
            "value": value,
            "source": source,
            "sources": _supporting_sources(ordered, lambda row: row.get(field), value),
        }
    return None


def _list_entries(facts: Iterable[dict], field: str) -> list[dict]:
    """Fusionne des listes compatibles ; la priorité ne sert qu'au libellé canonique."""
    selected: dict[str, dict] = {}
    for fact in _ordered_facts(facts):
        source = _text(fact.get("source"))
        values = fact.get(field)
        if not isinstance(values, list):
            continue
        for raw in values:
            value = _text(raw)
            key = _norm(value)
            if not key or key in UNKNOWN_VALUES:
                continue
            entry = selected.get(key)
            if entry is None:
                selected[key] = {"value": value, "source": source, "sources": [source] if source else []}
            elif source and source not in entry["sources"]:
                entry["sources"].append(source)
    return list(selected.values())


def _scope_kind(record: dict) -> str:
    explicit = _norm(record.get("kind"))
    scope = _norm(record.get("scope"))
    combined = f"{explicit} {scope}".strip()
    if any(marker in combined for marker in ("unique", "dedupli", "deduplic")):
        return "unique"
    if any(marker in combined for marker in ("total", "ensemble", "all")):
        return "total"
    return explicit or scope or "unspecified"


def _count_semantic(record: dict) -> tuple[str, str]:
    """Clé métier : unité + portée ; records total et uniques restent distincts."""
    unit = _norm(record.get("unit")) or "unknown"
    return unit, _scope_kind(record)


def _status(record: dict) -> str:
    value = _norm(record.get("status")) or "unknown"
    return value if value in STATUS_LABELS else "unknown"


def _record_value(record: dict) -> Any:
    value = record.get("value")
    if value is None:
        return _text(record.get("raw"))
    return value


def _same_record_value(left: dict, right: dict) -> bool:
    return _norm(_record_value(left)) == _norm(_record_value(right))


def _merge_record(existing: dict, record: dict, source: str) -> dict:
    if source and source not in existing["sources"]:
        existing["sources"].append(source)
    if _same_record_value(existing, record):
        return existing
    # Conflit sur la même sémantique : le premier en ordre de priorité gagne.
    return existing


def resolve_affected_counts(facts: Iterable[dict]) -> list[dict]:
    selected: dict[tuple[str, str], dict] = {}
    ordered = _ordered_facts(facts)
    for fact in ordered:
        source = _text(fact.get("source"))
        records = fact.get("rich_facts", {}).get("affected_counts", []) if isinstance(fact.get("rich_facts"), dict) else []
        if not isinstance(records, list):
            records = []
        for raw_record in records:
            if not isinstance(raw_record, dict) or raw_record.get("value") is None:
                continue
            record = dict(raw_record)
            key = _count_semantic(record)
            if key not in selected:
                selected[key] = {
                    **record,
                    "semantic": key[1],
                    "status": _status(record),
                    "source": source,
                    "sources": [source] if source else [],
                }
            else:
                _merge_record(selected[key], record, source)

    # Fallback pour les extracteurs historiques qui ne publient pas rich_facts.
    if not selected:
        for fact in ordered:
            value = fact.get("affected_count")
            if value is None:
                continue
            unit = _text(fact.get("affected_unit")) or "unknown"
            record = {
                "value": value,
                "raw": _text(fact.get("affected_count_raw")),
                "unit": unit,
                "semantic": "unspecified",
                "status": _norm(fact.get("claim_status")) or "unknown",
                "source": _text(fact.get("source")),
                "sources": [_text(fact.get("source"))] if _text(fact.get("source")) else [],
            }
            selected[(unit, "unspecified")] = record
            break
    return list(selected.values())


def _resolve_rich_entities(facts: Iterable[dict], key: str) -> list[dict]:
    selected: dict[str, dict] = {}
    for fact in _ordered_facts(facts):
        source = _text(fact.get("source"))
        rich = fact.get("rich_facts") if isinstance(fact.get("rich_facts"), dict) else {}
        records = rich.get(key, []) if isinstance(rich, dict) else []
        if not isinstance(records, list):
            continue
        for raw_record in records:
            if not isinstance(raw_record, dict):
                continue
            value = _text(raw_record.get("value"))
            if not value:
                continue
            semantic = _norm(raw_record.get("kind")) or _norm(raw_record.get("scope")) or _norm(value)
            if semantic not in selected:
                selected[semantic] = {
                    "value": value,
                    "status": _status(raw_record),
                    "source": source,
                    "sources": [source] if source else [],
                }
            elif source and source not in selected[semantic]["sources"]:
                selected[semantic]["sources"].append(source)
    return list(selected.values())


def _format_count(record: dict) -> str:
    raw = _text(record.get("raw"))
    if raw:
        return raw
    try:
        value = f"{int(record.get('value')):,}".replace(",", " ")
    except (TypeError, ValueError):
        value = _text(record.get("value"))
    unit = UNIT_LABELS.get(_text(record.get("unit")).lower(), _text(record.get("unit")))
    semantic = _text(record.get("semantic"))
    if semantic == "unique" and unit == "enregistrements":
        unit = "enregistrements uniques"
    return " ".join(part for part in (value, unit) if part).strip()


def build_display_summary(resolved: dict, fallback: str = "") -> str:
    """Produit une synthèse courte, déterministe et sans LLM."""
    sentences: list[str] = []
    affected = resolved.get("affected") or []
    if affected:
        record = affected[0]
        value = _format_count(record)
        status = STATUS_LABELS.get(_text(record.get("status")), "documenté")
        if value:
            sentences.append(f"{value[0].upper() + value[1:]} ({status}).")

    data_types = [entry.get("value") for entry in (resolved.get("data_types") or []) if entry.get("value")]
    if data_types:
        shown = ", ".join(data_types[:5])
        suffix = "…" if len(data_types) > 5 else ""
        sentences.append(f"Données exposées : {shown}{suffix}.")

    if sentences:
        return " ".join(sentences)
    return _text(fallback)


def resolve_incident_facts(facts: Iterable[dict], *, fallback_summary: str = "") -> dict:
    ordered = _ordered_facts(facts)
    resolved = {
        "version": 2,
        "fields": {field: value for field in SCALAR_FIELDS if (value := resolve_scalar(ordered, field))},
        "data_types": _list_entries(ordered, "data_types"),
        "vulnerabilities": _list_entries(ordered, "vulnerabilities"),
        "affected": resolve_affected_counts(ordered),
        "systems": _resolve_rich_entities(ordered, "affected_systems"),
        "datasets": _resolve_rich_entities(ordered, "affected_datasets"),
    }
    resolved["display_summary"] = build_display_summary(resolved, fallback=fallback_summary)
    return resolved


def resolve_all(raw_by_incident: dict[str, list[dict]], summaries: dict[str, str] | None = None) -> dict[str, dict]:
    summaries = summaries or {}
    return {
        incident_id: resolve_incident_facts(facts, fallback_summary=summaries.get(incident_id, ""))
        for incident_id, facts in raw_by_incident.items()
        if facts
    }
