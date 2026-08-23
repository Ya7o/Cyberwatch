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
from .headline import is_publishable_headline

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
    return _norm(record.get("unit")) or "unknown", _scope_kind(record)


def _status(record: dict) -> str:
    value = _norm(record.get("status")) or "unknown"
    return value if value in STATUS_LABELS else "unknown"


def _record_value(record: dict) -> Any:
    value = record.get("value")
    return value if value is not None else _text(record.get("raw"))


def _same_record_value(left: dict, right: dict) -> bool:
    left_value = left.get("value")
    right_value = right.get("value")
    if left_value is not None and right_value is not None:
        return str(left_value) == str(right_value)
    return _norm(_record_value(left)) == _norm(_record_value(right))


def _merge_record(existing: dict, record: dict, source: str) -> None:
    if source and source not in existing["sources"] and _same_record_value(existing, record):
        existing["sources"].append(source)


def _legacy_affected_record(fact: dict) -> dict | None:
    value = fact.get("affected_count")
    unit = _norm(fact.get("affected_unit"))
    if value is None or not unit or unit == "unknown":
        return None
    source = _text(fact.get("source"))
    return {
        "value": value,
        "raw": _text(fact.get("affected_count_raw")),
        "unit": unit,
        "semantic": "unspecified",
        "status": _status({"status": fact.get("claim_status")}),
        "source": source,
        "sources": [source] if source else [],
    }


def _rich_count_records(fact: dict) -> list[dict]:
    source = _text(fact.get("source"))
    rich = fact.get("rich_facts") if isinstance(fact.get("rich_facts"), dict) else {}
    records = rich.get("affected_counts", []) if isinstance(rich, dict) else []
    result: list[dict] = []
    if not isinstance(records, list):
        return result
    for raw in records:
        if not isinstance(raw, dict) or raw.get("value") is None:
            continue
        key = _count_semantic(raw)
        result.append({
            **raw,
            "unit": key[0],
            "semantic": key[1],
            "status": _status(raw),
            "source": source,
            "sources": [source] if source else [],
        })
    return result


def resolve_affected_counts(facts: Iterable[dict]) -> list[dict]:
    """Fusionne rich + legacy, sans perdre les mesures complémentaires.

    Un legacy sans portée explicite hérite d'une sémantique rich uniquement
    lorsqu'il n'existe qu'une seule portée possible pour cette unité. Si deux
    portées existent (ex. records total + unique), il reste ``unspecified`` afin
    de ne jamais inventer la nature du nombre.
    """
    ordered = _ordered_facts(facts)
    rich_by_fact = {id(fact): _rich_count_records(fact) for fact in ordered}
    rich_semantics: dict[str, set[str]] = {}
    for records in rich_by_fact.values():
        for record in records:
            rich_semantics.setdefault(record["unit"], set()).add(record["semantic"])

    selected: dict[tuple[str, str], dict] = {}
    for fact in ordered:
        source = _text(fact.get("source"))
        for record in rich_by_fact[id(fact)]:
            key = (record["unit"], record["semantic"])
            if key not in selected:
                selected[key] = record
            else:
                _merge_record(selected[key], record, source)

        legacy = _legacy_affected_record(fact)
        if not legacy:
            continue
        same_unit = [entry for (unit, _), entry in selected.items() if unit == legacy["unit"]]
        exact = next((entry for entry in same_unit if _same_record_value(entry, legacy)), None)
        if exact is not None:
            _merge_record(exact, legacy, source)
            continue

        semantics = rich_semantics.get(legacy["unit"], set())
        if len(semantics) == 1:
            legacy["semantic"] = next(iter(semantics))
        key = (legacy["unit"], legacy["semantic"])
        if key not in selected:
            selected[key] = legacy
        else:
            _merge_record(selected[key], legacy, source)

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


def _data_types_entries(facts: Iterable[dict]) -> list[dict]:
    """Fusionne `data_types` legacy (liste plate) et rich (`rich_facts.data_types`).

    Traite chaque fait dans l'ordre de priorité des sources, legacy et rich
    ensemble, pour que la priorité s'applique uniformément aux deux formats
    plutôt que de privilégier arbitrairement l'un des deux formats en bloc.
    """
    selected: dict[str, dict] = {}

    def add(value: str, source: str) -> None:
        key = _norm(value)
        if not key or key in UNKNOWN_VALUES:
            return
        entry = selected.get(key)
        if entry is None:
            selected[key] = {"value": value, "source": source, "sources": [source] if source else []}
        elif source and source not in entry["sources"]:
            entry["sources"].append(source)

    for fact in _ordered_facts(facts):
        source = _text(fact.get("source"))
        legacy = fact.get("data_types")
        if isinstance(legacy, list):
            for raw in legacy:
                add(_text(raw), source)
        rich = fact.get("rich_facts") if isinstance(fact.get("rich_facts"), dict) else {}
        rich_values = rich.get("data_types") if isinstance(rich, dict) else None
        if isinstance(rich_values, list):
            for raw_record in rich_values:
                if isinstance(raw_record, dict):
                    add(_text(raw_record.get("value")), source)
    return list(selected.values())


def _claim_entries(facts: Iterable[dict]) -> list[dict]:
    """Conserve les affirmations riches, avec leur preuve, pour la synthèse.

    Les claims ne sont pas réduits à leur seule valeur : la preuve est le
    contenu éditorial utile quand aucun impact structuré n'est disponible.
    """
    selected: dict[tuple[str, str, str], dict] = {}
    for fact in _ordered_facts(facts):
        source = _text(fact.get("source"))
        rich = fact.get("rich_facts") if isinstance(fact.get("rich_facts"), dict) else {}
        records = rich.get("claims", []) if isinstance(rich, dict) else []
        if not isinstance(records, list):
            continue
        for raw_record in records:
            if not isinstance(raw_record, dict):
                continue
            evidence = _text(raw_record.get("evidence"))
            if not evidence:
                continue
            value = raw_record.get("value")
            key = (_norm(raw_record.get("type")), _norm(value), _norm(evidence))
            if key in selected:
                if source and source not in selected[key]["sources"]:
                    selected[key]["sources"].append(source)
                continue
            selected[key] = {
                "value": value,
                "type": _text(raw_record.get("type")),
                "status": _status(raw_record),
                "evidence": evidence,
                "source": source,
                "sources": [source] if source else [],
            }
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
    if _text(record.get("semantic")) == "unique" and unit == "enregistrements":
        unit = "enregistrements uniques"
    return " ".join(part for part in (value, unit) if part).strip()


def _summary_priority(record: dict) -> tuple[int, int, int]:
    unit = _text(record.get("unit")).lower()
    semantic = _text(record.get("semantic")).lower()
    unit_rank = {"people": 0, "clients": 1, "users": 2, "accounts": 3, "records": 4, "files": 5}.get(unit, 9)
    semantic_rank = 0 if semantic == "unique" else 1 if semantic == "total" else 2
    return unit_rank, semantic_rank, source_rank(record.get("source"))


#: Longueur minimale d'un fallback narratif pour qu'il soit préféré à une
#: synthèse réduite à une métrique brute (§ build_display_summary).
_SUBSTANTIAL_FALLBACK_CHARS = 40
_SUMMARY_TECHNICAL_RE = re.compile(
    r"\b(?:header\s+html|javascript|css|vitesse\s+d[’']apparition|chargement|"
    r"donn[ée]es\s+expos[ée]es\s*:|[ée]l[ée]ments\s+document[ée]s\s*:)", re.I,
)
_SUMMARY_GENERIC_RE = re.compile(
    r"^(?:l[’']incident|la\s+cyberattaque|l[’']attaque|la\s+fuite)\s+.*"
    r"(?:exfiltration|fuite)\s+de\s+donn[ée]es\.?$", re.I,
)
_SUMMARY_GENERIC_CONFIRMATION_RE = re.compile(
    r"\b(?:confirme|a\s+confirm[ée])\b.*\bexfiltration\s+de\s+donn[ée]es\b.*\bincident\s+de\s+cybers[ée]curit[ée]\b",
    re.I,
)
_SUMMARY_METRIC_RE = re.compile(r"^\d[\d\s,.]*(?:enregistrements|fichiers|comptes|personnes|clients)\b", re.I)


def is_publishable_summary(value: str) -> bool:
    text = _text(value)
    if not is_publishable_headline(text):
        return False
    if (_SUMMARY_GENERIC_CONFIRMATION_RE.search(text)
            or _SUMMARY_METRIC_RE.match(text)):
        return False
    return True


def build_display_summary(resolved: dict, fallback: str = "") -> str:
    # Une carte ne réassemble jamais impact, volumes ou catégories. Ces faits
    # restent dans le détail ; seul le résumé éditorial déjà validé est publié.
    clean_fallback = _text(fallback)
    if is_publishable_summary(clean_fallback):
        return clean_fallback
    return ""


def resolve_incident_facts(facts: Iterable[dict], *, fallback_summary: str = "") -> dict:
    ordered = _ordered_facts(facts)
    resolved = {
        "version": 2,
        "fields": {field: value for field in SCALAR_FIELDS if (value := resolve_scalar(ordered, field))},
        "data_types": _data_types_entries(ordered),
        "vulnerabilities": _list_entries(ordered, "vulnerabilities"),
        "affected": resolve_affected_counts(ordered),
        "systems": _resolve_rich_entities(ordered, "affected_systems"),
        "datasets": _resolve_rich_entities(ordered, "affected_datasets"),
    }
    # Les claims sont déjà publiés dans chaque fait source. Ils servent ici à
    # composer la synthèse canonique sans dupliquer tout leur détail dans la
    # vue résolue par incident.
    resolved["display_summary"] = build_display_summary(
        {**resolved, "claims": _claim_entries(ordered)}, fallback=fallback_summary
    )
    return resolved


def resolve_all(raw_by_incident: dict[str, list[dict]], summaries: dict[str, str] | None = None) -> dict[str, dict]:
    summaries = summaries or {}
    return {
        incident_id: resolve_incident_facts(facts, fallback_summary=summaries.get(incident_id, ""))
        for incident_id, facts in raw_by_incident.items()
        if facts
    }
