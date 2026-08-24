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
    "unknown": "inconnu",
    "unconfirmed": "non confirmé",
    "denied": "démenti",
    "negated": "démenti",
    "hypothesis": "hypothèse",
}
_NUMERIC_ONLY_RE = re.compile(r"^[\d\s,.;: ]+$")
_MAX_DATA_TYPE_CHARS = 120
_ACTOR_PREFIX_RE = re.compile(
    r"^(?:(?:le|la|un|une)\s+(?:cybercriminel|hacker|pirate|"
    r"attaquant|acteur|groupe|collectif|gang)|(?:cybercriminel|hacker|"
    r"pirate|attaquant|groupe|collectif|gang))\s+",
    re.I,
)


def source_rank(source_id: str | None) -> int:
    return _SOURCE_RANK.get(str(source_id or "").strip(), len(SOURCE_PRIORITY) + 100)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _norm(value: Any) -> str:
    text = unicodedata.normalize("NFD", _text(value))
    text = "".join(char for char in text if unicodedata.category(char) != "Mn")
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def _actor_label(value: Any) -> str:
    """Conserve le nom de l'acteur, jamais sa désignation narrative.

    Les extracteurs peuvent citer « le cybercriminel misere » : c'est une
    preuve utile, mais le champ canonique doit être `misere` afin de rester
    comparable entre les sources et les runs zéro.
    """
    return _ACTOR_PREFIX_RE.sub("", _text(value)).strip(" ,;:-")


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
        value = _actor_label(fact.get(field)) if field == "threat_actor" else fact.get(field)
        if not _known(value):
            continue
        source = _text(fact.get("source"))
        return {
            "value": value,
            "source": source,
            "sources": _supporting_sources(
                ordered,
                (lambda row: _actor_label(row.get(field))) if field == "threat_actor" else (lambda row: row.get(field)),
                value,
            ),
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
    records = list(rich.get("affected_counts", []) if isinstance(rich, dict) else [])
    # Certains exports historiques de claims ont perdu leur champ ``type``
    # mais ont conservé valeur, unité et preuve. On répare seulement cette
    # forme objectivable ; aucun texte libre n'est promu en volume.
    for claim in rich.get("claims", []) if isinstance(rich, dict) else []:
        if not isinstance(claim, dict):
            continue
        value = _text(claim.get("value"))
        evidence = _text(claim.get("evidence"))
        unit = _norm(claim.get("unit"))
        if not re.fullmatch(r"\d+", value):
            continue
        evidence_norm = _norm(evidence)
        if not unit:
            if any(marker in evidence_norm for marker in ("assure", "personne", "client", "utilisateur")):
                unit = "people"
            elif any(marker in evidence_norm for marker in ("iban", "compte bancaire", "comptes")):
                unit = "accounts"
            elif any(marker in evidence_norm for marker in ("ligne", "enregistrement")):
                unit = "records"
        if unit:
            records.append({**claim, "value": int(value), "unit": unit, "raw": _text(claim.get("raw")) or value})
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

    # La clé inclut la valeur : deux chiffres différents peuvent être tous les
    # deux sourcés (total, échantillon, comptage d'un acteur). Les écraser par
    # priorité de source détruit une information utile et fausse l'audit.
    selected: dict[tuple[str, str, str], dict] = {}
    for fact in ordered:
        source = _text(fact.get("source"))
        for record in rich_by_fact[id(fact)]:
            key = (record["unit"], record["semantic"], _norm(_record_value(record)))
            if key not in selected:
                selected[key] = record
            else:
                _merge_record(selected[key], record, source)

        legacy = _legacy_affected_record(fact)
        if not legacy:
            continue
        same_unit = [entry for (unit, _, _), entry in selected.items() if unit == legacy["unit"]]
        exact = next((entry for entry in same_unit if _same_record_value(entry, legacy)), None)
        if exact is not None:
            _merge_record(exact, legacy, source)
            continue

        semantics = rich_semantics.get(legacy["unit"], set())
        if len(semantics) == 1:
            legacy["semantic"] = next(iter(semantics))
        key = (legacy["unit"], legacy["semantic"], _norm(_record_value(legacy)))
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
        records = list(rich.get(key, []) if isinstance(rich, dict) else [])
        # Les extracteurs sémantiques peuvent conserver un système ou un
        # périmètre dans claims : il doit arriver au même contrat public.
        claim_type = "system" if key == "affected_systems" else "dataset"
        records.extend(
            row for row in (rich.get("claims", []) if isinstance(rich, dict) else [])
            if isinstance(row, dict) and _norm(row.get("type")) == claim_type
        )
        if not isinstance(records, list):
            continue
        for raw_record in records:
            if not isinstance(raw_record, dict):
                continue
            value = _text(raw_record.get("value"))
            if not value:
                continue
            if key == "affected_systems" and any(marker in _norm(value) for marker in ("prestataire", "fournisseur", "sous traitant", "tiers")):
                # Un tiers est un contexte de compromission, pas un système de
                # la victime. Il est affiché dans son champ dédié.
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

    def add(value: str, source: str, status: str = "") -> None:
        # A type mentioned only to say it was *not* exposed is useful in the
        # source-level audit trail, but must never become a public "Données
        # exposées" chip.  Otherwise a denial such as "aucun IBAN identifié"
        # is presented as the exact opposite fact.
        if _norm(status) in {"negated", "denied"}:
            return
        key = _norm(value)
        if not key or key in UNKNOWN_VALUES or len(value) > _MAX_DATA_TYPE_CHARS or _NUMERIC_ONLY_RE.fullmatch(value):
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
                    add(_text(raw_record.get("value")), source, _text(raw_record.get("status")))
    return list(selected.values())


_RAW_RELATION_TRIPLE = re.compile(r"^.+ → .+ → .+$")


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
            if _RAW_RELATION_TRIPLE.match(_text(value)):
                # Filet contre un format interne "sujet → relation → objet" qui a pu
                # être stocké par un collecteur avant correction (jamais une phrase
                # publiable) — la relation, si utile, est déjà traduite ailleurs par
                # _relation_claim_entries().
                continue
            claim_type = _text(raw_record.get("type")) or _text(raw_record.get("kind")) or _infer_claim_type(raw_record)
            key = (_norm(claim_type), _norm(value), _norm(evidence))
            if key in selected:
                if source and source not in selected[key]["sources"]:
                    selected[key]["sources"].append(source)
                continue
            selected[key] = {
                "value": value,
                "type": claim_type,
                "status": _status(raw_record),
                "evidence": evidence,
                "actor": _text(raw_record.get("actor")),
                "date": _text(raw_record.get("date")),
                "scope": _text(raw_record.get("scope")),
                "unit": _text(raw_record.get("unit")),
                "source": source,
                "sources": [source] if source else [],
            }
    return list(selected.values())


def _infer_claim_type(record: dict) -> str:
    """Répare les claims v2 tronqués sans transformer du texte libre en fait.

    Les formes acceptées sont objectivables par unité, relation ou tournure de
    preuve ; sinon elles restent des ``statement`` visibles mais non projetées
    dans un champ métier.
    """
    value, evidence = _text(record.get("value")), _norm(record.get("evidence"))
    if re.fullmatch(r"\d+", value) and _text(record.get("unit")):
        return "affected_count"
    actor_words = _norm(value).split()
    generic_actor = {"fuite", "donnees", "publication", "incident", "cyberattaque", "vol", "compromission", "acces", "extraction"}
    if (
        "revendique" in evidence and value and not re.fullmatch(r"\d+", value)
        and 1 <= len(actor_words) <= 2 and not any(word in generic_actor for word in actor_words)
    ):
        return "actor"
    if any(marker in evidence for marker in ("mise en vente", "publie", "publication", "diffuse")):
        return "publication"
    if any(marker in evidence for marker in ("acces et extraction", "extraction des donnees", "compromission", "intrusion")):
        return "attack_action"
    return "statement"


def _relation_claim_entries(facts: Iterable[dict]) -> list[dict]:
    rows: list[dict] = []
    for fact in _ordered_facts(facts):
        source = _text(fact.get("source"))
        rich = fact.get("rich_facts") if isinstance(fact.get("rich_facts"), dict) else {}
        for relation in rich.get("relations", []) if isinstance(rich, dict) else []:
            if not isinstance(relation, dict):
                continue
            subject, kind, obj, evidence = (_text(relation.get(key)) for key in ("subject", "relation", "object", "evidence"))
            if not subject or not kind or not obj or not evidence:
                continue
            if kind == "claimed_by":
                # Les deux orientations existent dans les extracteurs : le
                # nom de l'organisation est souvent l'objet, sinon l'acteur.
                candidates = (subject, obj) if _norm(obj) in {"incident", "cyberattaque"} else (obj, subject)
                actor = next((candidate for candidate in candidates if _infer_claim_type({"value": candidate, "evidence": "revendique"}) == "actor"), "")
                if actor:
                    rows.append({"type": "actor", "value": actor, "status": _status(relation), "evidence": evidence, "source": source, "sources": [source] if source else []})
            elif kind == "compromised_via":
                if any(marker in _norm(obj) for marker in ("prestataire", "fournisseur", "sous traitant", "tiers")):
                    rows.append({"type": "third_party", "value": obj, "status": _status(relation), "evidence": evidence, "source": source, "sources": [source] if source else []})
    return rows


def _evidence_claim_entries(facts: Iterable[dict]) -> list[dict]:
    """Expose le tiers explicitement nommé dans une preuve même sans valeur.

    Ce filet ne crée qu'un libellé générique (« prestataire technique ») : il
    ne prétend jamais connaître l'identité du tiers lorsque l'article ne la
    communique pas.
    """
    rows: list[dict] = []
    marker = re.compile(r"\b(prestataire(?:\s+technique)?|fournisseur|sous[- ]traitant)\b", re.I)
    for fact in _ordered_facts(facts):
        source = _text(fact.get("source"))
        rich = fact.get("rich_facts") if isinstance(fact.get("rich_facts"), dict) else {}
        for claim in rich.get("claims", []) if isinstance(rich, dict) else []:
            if not isinstance(claim, dict):
                continue
            evidence = _text(claim.get("evidence"))
            match = marker.search(evidence)
            if match:
                rows.append({"type": "third_party", "value": match.group(1).lower(), "status": _status(claim), "evidence": evidence, "source": source, "sources": [source] if source else []})
    return rows


def _dedupe_claim_entries(entries: Iterable[dict]) -> list[dict]:
    selected: dict[tuple[str, str], dict] = {}
    for entry in entries:
        key = (_norm(entry.get("type")), _norm(entry.get("value")))
        if not key[0] or not key[1]:
            continue
        previous = selected.get(key)
        if previous is None:
            selected[key] = entry
        else:
            for source in entry.get("sources", []):
                if source and source not in previous["sources"]:
                    previous["sources"].append(source)
    return list(selected.values())


def _claim_scalar(claims: Iterable[dict], claim_type: str) -> dict | None:
    candidates = [claim for claim in claims if claim.get("type") == claim_type and _known(claim.get("value"))]
    if claim_type == "actor":
        # Un nom d'acteur doit figurer dans l'extrait de preuve : un modèle ne
        # peut pas propager un autre acteur simplement cité dans l'article.
        candidates = [
            claim for claim in candidates
            if _norm(claim.get("value")) in _norm(claim.get("evidence"))
        ]
    if not candidates:
        return None
    claim = sorted(candidates, key=lambda row: (source_rank(row.get("source")), _text(row.get("value"))))[0]
    return {"value": claim["value"], "source": claim.get("source", ""), "sources": claim.get("sources", [])}


def _timeline_entries(facts: Iterable[dict]) -> list[dict]:
    selected: dict[tuple[str, str, str], dict] = {}
    for fact in _ordered_facts(facts):
        source = _text(fact.get("source"))
        rich = fact.get("rich_facts") if isinstance(fact.get("rich_facts"), dict) else {}
        for row in rich.get("timeline", []) if isinstance(rich, dict) else []:
            if not isinstance(row, dict):
                continue
            date, event, evidence = _text(row.get("date")), _text(row.get("event")), _text(row.get("evidence"))
            if not event or not evidence:
                continue
            key = (_norm(date), _norm(event), _norm(evidence))
            if key not in selected:
                selected[key] = {"date": date, "event": event, "status": _status(row), "evidence": evidence, "source": source, "sources": [source] if source else []}
            elif source and source not in selected[key]["sources"]:
                selected[key]["sources"].append(source)
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


def is_publishable_summary(value: str, *, organisation: str = "") -> bool:
    """Retourne si une headline peut être affichée sur une carte incident.

    Une valeur égale au nom canonique de l'organisation est une ancienne
    valeur de repli, pas une synthèse. Cette vérification doit aussi couvrir
    les faits historiques qui n'ont pas nécessairement traversé SourceFacts.
    """
    text = _text(value)
    if not is_publishable_headline(text):
        return False
    if organisation and _norm(text) == _norm(organisation):
        return False
    if (_SUMMARY_GENERIC_CONFIRMATION_RE.search(text)
            or _SUMMARY_METRIC_RE.match(text)):
        return False
    return True


def best_publishable_summary(facts: Iterable[dict], *, organisation: str = "") -> str:
    """Choisit la meilleure headline déjà validée, jamais un détail structuré."""
    candidates = []
    for fact in _ordered_facts(facts):
        value = _text(fact.get("summary"))
        if not is_publishable_summary(value, organisation=organisation):
            continue
        richness = sum(bool(fact.get(key)) for key in ("impact", "affected_count", "data_types", "threat_actor"))
        candidates.append((richness, -source_rank(fact.get("source")), value))
    return max(candidates)[2] if candidates else ""


def build_display_summary(resolved: dict, fallback: str = "") -> str:
    # Une carte ne réassemble jamais impact, volumes ou catégories. Ces faits
    # restent dans le détail ; seul le résumé éditorial déjà validé est publié.
    clean_fallback = _text(fallback)
    if is_publishable_summary(clean_fallback):
        return clean_fallback
    return ""


def resolve_incident_facts(facts: Iterable[dict], *, fallback_summary: str = "", organisation: str = "") -> dict:
    ordered = _ordered_facts(facts)
    claims = _dedupe_claim_entries(_claim_entries(ordered) + _relation_claim_entries(ordered) + _evidence_claim_entries(ordered))
    organisation_norm = _norm(organisation)
    if organisation_norm:
        claims = [
            claim for claim in claims
            if not (
                claim.get("type") == "actor"
                and (_norm(claim.get("value")) == organisation_norm
                     or organisation_norm in _norm(claim.get("value"))
                     or _norm(claim.get("value")) in organisation_norm)
            )
        ]
    fields = {field: value for field in SCALAR_FIELDS if (value := resolve_scalar(ordered, field))}
    # Les scalaires explicitement extraits restent prioritaires. Les claims
    # typés constituent uniquement un filet de provenance pour les acteurs et
    # tiers, dont l'absence de projection ne doit plus vider une fiche riche.
    for field, claim_type in (("threat_actor", "actor"), ("third_party", "third_party")):
        fields.setdefault(field, _claim_scalar(claims, claim_type))
    resolved = {
        "version": 3,
        "fields": {field: value for field, value in fields.items() if value},
        "data_types": _data_types_entries(ordered),
        "vulnerabilities": _list_entries(ordered, "vulnerabilities"),
        "affected": resolve_affected_counts(ordered),
        "systems": _resolve_rich_entities(ordered, "affected_systems"),
        "datasets": _resolve_rich_entities(ordered, "affected_datasets"),
        "claims": claims,
        "timeline": _timeline_entries(ordered),
    }
    # Les claims sont déjà publiés dans chaque fait source. Ils servent ici à
    # composer la synthèse canonique sans dupliquer tout leur détail dans la
    # vue résolue par incident.
    resolved["display_summary"] = build_display_summary(
        resolved, fallback=fallback_summary
    )
    return resolved


def resolve_all(
    raw_by_incident: dict[str, list[dict]],
    summaries: dict[str, str] | None = None,
    organisations: dict[str, str] | None = None,
) -> dict[str, dict]:
    summaries = summaries or {}
    organisations = organisations or {}
    return {
        incident_id: resolve_incident_facts(
            facts,
            fallback_summary=summaries.get(incident_id, ""),
            organisation=organisations.get(incident_id, ""),
        )
        for incident_id, facts in raw_by_incident.items()
        if facts
    }
