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
from .normalize import (
    canonical_data_type,
    extract_unique_value_counts,
    is_recognized_data_type,
    parse_date,
)

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


#: Cas réel constaté (audit 2026-08-25) : l'extraction LLM capte parfois le
#: sujet grammatical d'un verbe déclaratif ("qui indique", "L'entreprise
#: indique") comme s'il s'agissait de l'acteur revendicateur, alors qu'il
#: s'agit d'un pronom relatif ou de la victime elle-même. Filet déterministe
#: gratuit en complément du prompt (source_facts_ai.py) : rejette ces deux
#: formes plutôt que de les publier comme un acteur nommé.
_ACTOR_PRONOUN_BLOCKLIST = {
    "qui", "il", "elle", "ils", "elles",
    "de", "et", "group", "groupe",
    "celui ci", "celle ci", "celui la", "celle la",
    "ce dernier", "cette derniere", "ces derniers", "ces dernieres",
    # Cas réel constaté après le fix du prompt (reset 2026-08-25, Emil Frey
    # France) : le LLM peut encore désigner la victime par une périphrase
    # générique plutôt que par son nom propre. Ces formes ne sont jamais un
    # acteur nommé, quelle que soit l'organisation concernée.
    "l entreprise", "la societe", "la victime", "l organisation",
    "la structure", "l etablissement", "la compagnie", "la firme",
    "l entite", "syndicat", "le syndicat", "association", "l association",
    "organisation", "entreprise", "societe", "victime",
    "prestataire", "fournisseur", "sous traitant", "tiers",
}

_VICTIM_DECLARATION_RE = re.compile(
    r"\b(?:informe|indique|confirme|a d[ée]tect[ée]|a [ée]t[ée] victime|"
    r"soci[ée]t[ée] derri[èe]re|personnes concern[ée]es|ses syst[èe]mes)\b",
    re.I,
)
_ATTACKER_ATTRIBUTION_RE = re.compile(
    r"\b(?:revendique|revendiqu[ée]e? par|attribu[ée]e? [àa]|responsable de|"
    r"attaquant|hacker|pirate|groupe cybercriminel)\b",
    re.I,
)


def _is_actor_value_valid(value: Any, organisation: str = "") -> bool:
    """Rejette un acteur qui n'est en réalité qu'un artefact grammatical :
    un pronom relatif/démonstratif capté devant un verbe déclaratif, ou le
    nom de la victime elle-même repris comme sujet de la phrase."""
    norm = _norm(value)
    if not norm or norm in _ACTOR_PRONOUN_BLOCKLIST:
        return False
    organisation_norm = _norm(organisation)
    if organisation_norm and (
        norm == organisation_norm
        or organisation_norm in norm
        or norm in organisation_norm
    ):
        return False
    return True


def _victim_actor_aliases(facts: Iterable[dict], organisation: str) -> list[str]:
    """Retrouve les noms de victime secondaires cités comme sujets déclarants.

    Une marque peut être publiée sous un autre nom que sa société opératrice
    (Allo E.Leclerc / L Commerce). Comparer seulement l'acteur au libellé de
    l'incident ne suffit alors pas à éliminer la victime captée comme acteur.
    """
    # Une chaîne vide conserve l'application de la blocklist générique
    # (`qui`, `l'entreprise`, etc.) même sans organisation connue.
    aliases = [organisation]
    for fact in _ordered_facts(facts):
        rich = fact.get("rich_facts") if isinstance(fact.get("rich_facts"), dict) else {}
        for claim in rich.get("claims", []) if isinstance(rich, dict) else []:
            if not isinstance(claim, dict) or _norm(claim.get("type")) != "actor":
                continue
            evidence = _text(claim.get("evidence"))
            value = _text(claim.get("value"))
            if (
                value
                and _VICTIM_DECLARATION_RE.search(evidence)
                and not _ATTACKER_ATTRIBUTION_RE.search(evidence)
                and all(_norm(value) != _norm(existing) for existing in aliases)
            ):
                aliases.append(value)
    return aliases


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


#: Champs qui décrivent l'incident lui-même : leur statut *est* celui que
#: l'article déclare sur l'incident. Tous les autres qualifient un élément
#: particulier et doivent porter leur propre preuve.
_ARTICLE_SCOPED_FIELDS = frozenset({"impact", "evolution"})

_FIELD_CONFIRMATION_RE = re.compile(r"\bconfirm[ée]?e?s?\b", re.I)


def _capped_scalar_status(field: str, status: str, evidence: str) -> str:
    """Empêche le statut global de l'incident de sacrer un champ non confirmé.

    `Claim_Status` qualifie l'incident, pas chaque champ : une phrase telle que
    « la collectivité confirme la cyberattaque » faisait publier un vecteur
    d'accès déduit d'une phrase pédagogique comme « confirmé ». Le statut est
    donc *plafonné*, jamais remplacé — un statut plus faible passe tel quel et
    ne peut que rester faible, sans quoi un « claimed » serait promu.
    """
    if field in _ARTICLE_SCOPED_FIELDS or field == "data_volume":
        return status
    if status == "confirmed" and not _FIELD_CONFIRMATION_RE.search(evidence or ""):
        return "reported"
    return status


def resolve_scalar(facts: Iterable[dict], field: str) -> dict | None:
    ordered = _ordered_facts(facts)
    for fact in ordered:
        value = _actor_label(fact.get(field)) if field == "threat_actor" else fact.get(field)
        if not _known(value):
            continue
        source = _text(fact.get("source"))
        evidence = _text(fact.get(f"{field}_evidence"))
        if field == "impact" and (
            _HYPOTHETICAL_EVIDENCE_RE.search(evidence or _text(value))
            or _NEGATED_EVIDENCE_RE.search(evidence or _text(value))
        ):
            continue
        resolved_status = _status({"status": fact.get("claim_status")})
        if field == "data_volume":
            rich = fact.get("rich_facts") if isinstance(fact.get("rich_facts"), dict) else {}
            volume_rows = rich.get("data_volumes") if isinstance(rich, dict) else []
            volume_record = next((
                row for row in (volume_rows if isinstance(volume_rows, list) else [])
                if isinstance(row, dict)
                and _status(row) not in {"negated", "denied", "hypothesis"}
            ), None)
            if volume_record:
                resolved_status = _status(volume_record)
                evidence = _text(volume_record.get("evidence")) or evidence
        if resolved_status == "confirmed" and re.search(r"\b(?:revendiqu|affirme)\w*\b", evidence, re.I):
            resolved_status = "claimed"
        resolved_status = _capped_scalar_status(field, resolved_status, evidence)
        result = {
            "value": value,
            "source": source,
            "sources": _supporting_sources(
                ordered,
                (lambda row: _actor_label(row.get(field))) if field == "threat_actor" else (lambda row: row.get(field)),
                value,
            ),
            # Statut déclaratif de la ligne source (confirmé/revendiqué/...),
            # republié pour que l'affichage porte le badge sur le champ lui
            # même plutôt que de le répéter dans une liste de faits séparée.
            "status": resolved_status,
        }
        if evidence:
            result["evidence"] = evidence
        return result
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


_STATUS_RANK = {
    "confirmed": 5,
    "reported": 4,
    "claimed": 3,
    "unknown": 2,
    "hypothesis": 1,
    "unconfirmed": 1,
    "denied": 0,
    "negated": 0,
}

_NEGATED_EVIDENCE_RE = re.compile(
    r"\b(?:ne|n['’])\b.{0,80}\b(?:pas|aucun|aucune|nullement)\b|"
    r"\b(?:ne sont pas|n'est pas|non concern[ée]s?|non expos[ée]s?)\b",
    re.I,
)
_HYPOTHETICAL_EVIDENCE_RE = re.compile(
    r"\b(?:pourrait|pourraient|permettrait|potentielle?|peut par exemple|"
    r"ne signifie toutefois pas)\b|"
    r"\brisque\b.{0,50}\bd(?:e|['’])\b|"
    r"\b(?:peut|peuvent)\b.{0,100}\bpermettre\b|"
    r"\b(?:peut|peuvent)\b.{0,100}\b(?:chercher|tenter|r[ée]cup[ée]r|obtenir|contenir|confirmer)|"
    r"\b(?:d[ée]terminer|savoir|v[ée]rifier)\s+si\b|"
    r"\bsi\b.{0,100}\b(?:[ée]t[ée]|avait|confirme|contient|concerne|comprend|inclut)|"
    r"\bil ne serait (?:donc )?pas justifi[ée]\b",
    re.I,
)
_INCIDENT_COUNT_CONTEXT_RE = re.compile(
    r"\b(?:incident|attaque|cyberattaque|fuite|expos[ée]|touch[ée]|concern[ée]|"
    r"affect[ée]|victime|compromis|exfiltr|vol[ée]|r[ée]cup[ée]r|revendiqu|"
    r"inform[ée]s? de l['’]incident|donn[ée]es?|enregistrements?)\b",
    re.I,
)
_BACKGROUND_COUNT_CONTEXT_RE = re.compile(
    r"\b(?:en circulation|dans (?:son|le) r[ée]seau|utilisateurs? particuliers|"
    r"professionnels? dans son r[ée]seau|membres? du r[ée]seau)\b",
    re.I,
)


def _better_status(left: str, right: str) -> str:
    left_status, right_status = _status({"status": left}), _status({"status": right})
    return right_status if _STATUS_RANK[right_status] > _STATUS_RANK[left_status] else left_status


def _incident_count_is_publishable(record: dict) -> bool:
    """Écarte les chiffres de contexte commercial pris pour des victimes.

    Un nombre sans preuve reste accepté pour compatibilité legacy. Dès qu'une
    preuve est disponible, un chiffre décrivant seulement la population ou le
    réseau de la victime doit porter un lien explicite avec l'incident.
    """
    if _status(record) in {"negated", "denied", "hypothesis"}:
        return False
    evidence = _text(record.get("evidence"))
    if not evidence:
        return True
    if _NEGATED_EVIDENCE_RE.search(evidence):
        return False
    if _BACKGROUND_COUNT_CONTEXT_RE.search(evidence) and not _INCIDENT_COUNT_CONTEXT_RE.search(evidence):
        return False
    return True


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


def _legacy_file_record(fact: dict) -> dict | None:
    value = fact.get("file_count")
    if value is None:
        return None
    try:
        numeric = int(value)
    except (TypeError, ValueError):
        return None
    if numeric <= 0:
        return None
    source = _text(fact.get("source"))
    evidence = _text(fact.get("file_count_evidence"))
    return {
        "value": numeric,
        "raw": "",
        "unit": "files",
        "semantic": "total",
        "status": _status({"status": fact.get("claim_status")}),
        "source": source,
        "sources": [source] if source else [],
        "evidence": evidence,
    }


def _rich_count_records(fact: dict) -> list[dict]:
    source = _text(fact.get("source"))
    rich = fact.get("rich_facts") if isinstance(fact.get("rich_facts"), dict) else {}
    records = list(rich.get("affected_counts", []) if isinstance(rich, dict) else [])
    # Certains exports historiques de claims ont perdu leur champ ``type``
    # mais ont conservé valeur, unité et preuve. D'autres ont conservé le type
    # `affected_count` mais pas l'unité et n'ont, par erreur, aucune copie dans
    # `affected_counts` (cas réel Euskal Moneta : 6 000 personnes informées).
    # On ne répare que les formes numériques objectivables, jamais du texte
    # libre, et uniquement lorsqu'aucun record équivalent n'existe déjà.
    represented_values = {
        _text(record.get("value"))
        for record in records
        if isinstance(record, dict) and record.get("value") is not None
    }
    for claim in rich.get("claims", []) if isinstance(rich, dict) else []:
        if not isinstance(claim, dict):
            continue
        claim_type = _norm(claim.get("type"))
        if claim_type and claim_type != "affected count":
            continue
        value = _text(claim.get("value"))
        if value in represented_values:
            continue
        evidence = _text(claim.get("evidence"))
        unit = _norm(claim.get("unit"))
        if not re.fullmatch(r"\d+", value):
            continue
        evidence_norm = _norm(evidence)
        if not unit:
            if any(marker in evidence_norm for marker in (
                "assure", "personne", "client", "utilisateur", "particulier",
                "professionnel", "adherent",
            )):
                unit = "people"
            elif any(marker in evidence_norm for marker in ("iban", "compte bancaire", "comptes")):
                unit = "accounts"
            elif any(marker in evidence_norm for marker in ("ligne", "enregistrement")):
                unit = "records"
        if unit:
            # Pas de repli sur la valeur brute non formatée : un `raw`
            # absent doit laisser le frontend formater (séparateurs de
            # milliers + unité), pas afficher un nombre nu sans unité.
            records.append({**claim, "value": int(value), "unit": unit, "raw": _text(claim.get("raw"))})
            represented_values.add(value)
    result: list[dict] = []
    if not isinstance(records, list):
        return result
    for raw in records:
        if not isinstance(raw, dict) or raw.get("value") is None:
            continue
        key = _count_semantic(raw)
        record = {
            **raw,
            "unit": key[0],
            "semantic": key[1],
            "status": _status(raw),
            "source": source,
            "sources": [source] if source else [],
        }
        if _incident_count_is_publishable(record):
            result.append(record)
    return result


def _rejected_rich_count_signatures(fact: dict) -> set[tuple[str, str]]:
    """Signatures rich rejetées qui doivent neutraliser leur doublon legacy."""
    rich = fact.get("rich_facts") if isinstance(fact.get("rich_facts"), dict) else {}
    rows = list(rich.get("affected_counts", []) if isinstance(rich, dict) else [])
    rows.extend(
        claim for claim in (rich.get("claims", []) if isinstance(rich, dict) else [])
        if isinstance(claim, dict) and _norm(claim.get("type")) == "affected count"
    )
    rejected: set[tuple[str, str]] = set()
    for row in rows:
        if not isinstance(row, dict) or row.get("value") is None:
            continue
        if not _incident_count_is_publishable(row):
            rejected.add((_norm(row.get("unit")) or "unknown", _text(row.get("value"))))
    return rejected


_SEMANTIC_INFORMATIVENESS = {"unique": 2, "total": 2, "unspecified": 0}


def _format_count(record: dict) -> str:
    """Texte affiché d'un volume, utilisé pour la déduplication visuelle."""
    raw = _text(record.get("raw"))
    if raw:
        return raw
    try:
        value = f"{int(record.get('value')):,}".replace(",", " ")
    except (TypeError, ValueError):
        value = _text(record.get("value"))
    unit = UNIT_LABELS.get(
        _text(record.get("unit")).lower(), _text(record.get("unit"))
    )
    if _text(record.get("semantic")) == "unique" and unit == "enregistrements":
        unit = "enregistrements uniques"
    return " ".join(part for part in (value, unit) if part).strip()


def _affected_display_key(record: dict) -> str:
    """Deux mesures qui s'affichent au même texte sont un doublon visuel.

    La clé porte donc sur le texte réellement rendu (`_format_count`), pas sur
    la présence du champ `raw`. Cas réel constaté (reset 2026-08-25, Groupe
    Bernard) : deux enregistrements de même valeur et même unité
    (330563/files) s'affichaient tous deux "330 563 fichiers" — l'un depuis
    son `raw`, l'autre reconstruit depuis `value`+`unit` faute de `raw`.
    L'ancienne clé les distinguait sur ce seul détail interne
    (`raw:330 563 fichiers` vs `files:330563`) et publiait donc deux puces
    identiques.
    """
    return _norm(_format_count(record))


def _rounding_power(value: int) -> int:
    """Plus grande puissance de 10 (>= 1000) dont `value` est multiple, 0 si
    `value` n'a pas la structure d'un chiffre arrondi (ex. 330000 -> 10000,
    330563 -> 0)."""
    if value <= 0 or value % 1000:
        return 0
    power = 1000
    while value % (power * 10) == 0:
        power *= 10
    return power


#: Écart relatif maximal toléré entre les deux valeurs (5 %) : un simple
#: rapprochement structurel ("10000 a la forme d'un arrondi") ne suffit pas
#: — sans ce plafond, 9000 et 10000 (deux chiffres réellement distincts,
#: cf. test_conflit_cross_format_meme_unite_conserve_les_mesures_distinctes)
#: seraient confondus puisque 10000 est structurellement l'arrondi au
#: millier de tout nombre entre 5000 et 15000.
_MAX_ROUNDING_RELATIVE_GAP = 0.05


def _numbers_are_rounding_pair(a: int, b: int) -> bool:
    """Vrai si l'un des deux chiffres est la version arrondie de l'autre à
    sa propre puissance de 10 (330000 est l'arrondi de 330563 au millier
    près ; 10000 est l'arrondi de 10073) ET que l'écart relatif entre les
    deux reste faible — une imprécision de rapport plausible, pas deux
    chiffres réellement différents."""
    if a == b:
        return False
    larger, smaller = (a, b) if a > b else (b, a)
    if smaller <= 0 or (larger - smaller) / larger > _MAX_ROUNDING_RELATIVE_GAP:
        return False
    for round_value, other in ((a, b), (b, a)):
        power = _rounding_power(round_value)
        if power and round(other / power) * power == round_value:
            return True
    return False


def _dedupe_affected_rounding(records: list[dict]) -> list[dict]:
    """Un chiffre rond et un chiffre précis du même ordre de grandeur, même
    unité, décrivent presque toujours le même fait rapporté avec une
    précision différente par deux sources — pas deux volumes distincts. Cas
    réels constatés (§audit 2026-08-25) : Groupe Bernard (330 563 vs
    330 000 fichiers), Banque Alimentaire de la Croix-Rouge à Strasbourg
    (10 073 vs 10 000). La valeur la plus précise (jamais "ronde") est
    conservée ; les sources du chiffre arrondi lui sont rattachées plutôt
    que d'afficher un doublon."""
    def sort_key(record: dict) -> tuple[int, int]:
        try:
            value = int(record.get("value"))
        except (TypeError, ValueError):
            return (0, 0)
        return (_rounding_power(value), -value)

    kept: list[dict] = []
    for record in sorted(records, key=sort_key):
        try:
            numeric = int(record.get("value"))
        except (TypeError, ValueError):
            kept.append(record)
            continue
        unit = _norm(record.get("unit"))
        match = next(
            (
                k for k in kept
                if _norm(k.get("unit")) == unit
                and isinstance(k.get("value"), int)
                and _numbers_are_rounding_pair(numeric, k["value"])
            ),
            None,
        )
        if match is None:
            kept.append(record)
            continue
        for source in record.get("sources") or []:
            if source not in match["sources"]:
                match["sources"].append(source)
    return kept


def _dedupe_affected_display(records: list[dict]) -> list[dict]:
    """Fusionne les entrées qui afficheraient le même texte (ex. "9 000
    clients") mais que la sémantique interne ("total" vs "unspecified")
    empêchait de dédupliquer plus haut. Ce doublon est invisible dans les
    données mais visible à l'écran — cas réel constaté sur Sport 2000."""
    grouped: dict[str, list[dict]] = {}
    for record in records:
        grouped.setdefault(_affected_display_key(record), []).append(record)
    result = []
    for group in grouped.values():
        if len(group) == 1:
            result.append(group[0])
            continue
        ranked = sorted(
            group,
            key=lambda r: (-_SEMANTIC_INFORMATIVENESS.get(_norm(r.get("semantic")), 1), _norm(r.get("semantic"))),
        )
        winner = dict(ranked[0])
        sources = list(winner.get("sources") or [])
        for other in ranked[1:]:
            for source in other.get("sources") or []:
                if source not in sources:
                    sources.append(source)
        winner["sources"] = sources
        result.append(winner)
    return result


def _dedupe_affected_same_evidence(records: list[dict]) -> list[dict]:
    """Fusionne deux projections du même chiffre issues de la même preuve.

    Les adaptateurs peuvent extraire une mesure à la fois comme compte rich
    et comme compte sémantique plus précis. Si valeur, unité et preuve sont
    identiques, les portées internes différentes ne justifient pas deux puces
    publiques. Le qualificatif brut (« environ ») et le meilleur statut sont
    conservés.
    """
    selected: dict[tuple[str, str, str], dict] = {}
    passthrough: list[dict] = []
    for record in records:
        # Deux extracteurs peuvent conserver ou retirer le sujet narratif
        # ("Le hacker Alduin affirme..." / "Alduin affirme..."). Il s'agit
        # néanmoins de la même phrase-source : neutraliser seulement ce
        # préfixe contrôlé évite le doublon sans fusionner deux preuves
        # réellement distinctes qui citeraient le même nombre.
        evidence = _norm(_ACTOR_PREFIX_RE.sub("", _text(record.get("evidence"))))
        if not evidence:
            passthrough.append(record)
            continue
        key = (_norm(record.get("unit")), _text(record.get("value")), evidence)
        existing = selected.get(key)
        if existing is None:
            selected[key] = dict(record)
            continue
        raw = _text(record.get("raw"))
        existing_raw = _text(existing.get("raw"))
        if raw and (
            not existing_raw
            or (re.search(r"\b(?:environ|pr[eè]s de|plus de|au moins)\b", raw, re.I)
                and not re.search(r"\b(?:environ|pr[eè]s de|plus de|au moins)\b", existing_raw, re.I))
        ):
            existing["raw"] = raw
        existing["status"] = _better_status(
            _text(existing.get("status")), _text(record.get("status"))
        )
        for source in record.get("sources", []) or []:
            if source and source not in existing.setdefault("sources", []):
                existing["sources"].append(source)
    return passthrough + list(selected.values())


def _looks_like_atomic_data_type(value: str) -> bool:
    """Distingue une catégorie de donnée d'un périmètre de données.

    ``is_recognized_data_type`` est volontairement tolérant : il reconnaît
    par exemple ``facturation`` au sein de "données de livraison et de
    facturation de Journaux.fr". Ce libellé complet décrit toutefois un jeu
    de données et doit rester dans le périmètre. Une catégorie atomique reste
    courte et proche de son libellé canonique.
    """
    if not is_recognized_data_type(value):
        return False
    canonical = _text(canonical_data_type(value))
    value_words = _norm(value).split()
    canonical_words = _norm(canonical).split()
    return bool(canonical_words) and len(value_words) <= len(canonical_words) + 2


def resolve_affected_counts(facts: Iterable[dict]) -> list[dict]:
    """Fusionne rich + legacy, sans perdre les mesures complémentaires.

    Un legacy sans portée explicite hérite d'une sémantique rich uniquement
    lorsqu'il n'existe qu'une seule portée possible pour cette unité. Si deux
    portées existent (ex. records total + unique), il reste ``unspecified`` afin
    de ne jamais inventer la nature du nombre.
    """
    ordered = _ordered_facts(facts)
    # Un chiffre explicitement démenti par l'article ("n'ont pas été
    # vérifiés", "ne correspondent pas nécessairement à...") ne doit jamais
    # s'afficher comme un fait ordinaire — même garde que _data_types_entries
    # pour negated/denied, jusqu'ici absente de ce côté (§audit 2026-08-25 :
    # cas réel YouFid 1,9M démenti affiché comme un second chiffre normal).
    rejected_signatures = {
        id(fact): _rejected_rich_count_signatures(fact)
        for fact in ordered
    }
    rich_by_fact = {
        id(fact): [
            record for record in _rich_count_records(fact)
            if record.get("status") not in {"negated", "denied", "hypothesis"}
            and not (
                record.get("status") == "unknown"
                and (_norm(record.get("unit")) or "unknown", _text(record.get("value")))
                in rejected_signatures[id(fact)]
            )
        ]
        for fact in ordered
    }
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

        file_record = _legacy_file_record(fact)
        if file_record and _incident_count_is_publishable(file_record):
            key = (file_record["unit"], file_record["semantic"], _norm(_record_value(file_record)))
            if key not in selected:
                selected[key] = file_record
            else:
                _merge_record(selected[key], file_record, source)

        legacy = _legacy_affected_record(fact)
        if not legacy or legacy.get("status") in {"negated", "denied"}:
            continue
        if (legacy["unit"], _text(legacy.get("value"))) in rejected_signatures[id(fact)]:
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

    rows = _dedupe_affected_same_evidence(list(selected.values()))
    return _dedupe_affected_rounding(_dedupe_affected_display(rows))
