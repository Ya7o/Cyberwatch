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
from .headline import (
    is_publishable_for_organisation,
    is_publishable_headline,
    victim_claims_incident,
)
from .normalize import (
    canonical_data_type,
    extract_unique_value_counts,
    is_recognized_data_type,
    parse_date,
)
from .fact_resolution_vulnerabilities import resolve_vulnerabilities

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
_NON_EXPOSURE_DATA_CONTEXT_RE = re.compile(
    r"\b(?:recommand\w*|conseill\w*)\b.{0,140}\b(?:communiquer|transmettre|partager)\b|"
    r"\b(?:peut|peuvent|pourrait|pourraient)\b.{0,100}\b(?:permettre|servir|chercher|"
    r"obtenir|r[ée]cup[ée]rer|r[ée]clamer)\b|"
    r"\b(?:renouvel\w*|r[ée]voqu\w*|d[ée]sactiv\w*|r[ée]initialis\w*|rotation)\b"
    r".{0,120}\b(?:cl[ée]s?|identifiants?|sessions?|mots? de passe|acc[èe]s)\b|"
    r"\b(?:prestataire|fournisseur|sous[- ]traitant|tiers)\b.{0,100}"
    r"\b(?:charg[ée]|sp[ée]cialis[ée]|intervenant)\b.{0,100}"
    r"\b(?:suivi|gestion)\b.{0,50}\b(?:commandes?|livraisons?|colis)\b",
    re.I,
)


from .fact_resolution_counts import (
    _BACKGROUND_COUNT_CONTEXT_RE,
    _HYPOTHETICAL_EVIDENCE_RE,
    _INCIDENT_COUNT_CONTEXT_RE,
    _NEGATED_EVIDENCE_RE,
    _STATUS_RANK,
    _actor_label,
    _better_status,
    _count_semantic,
    _dedupe_affected_display,
    _dedupe_affected_rounding,
    _dedupe_affected_same_evidence,
    _incident_count_is_publishable,
    _is_actor_value_valid,
    _known,
    _legacy_affected_record,
    _looks_like_atomic_data_type,
    _merge_record,
    _norm,
    _ordered_facts,
    _record_value,
    _rejected_rich_count_signatures,
    _rich_count_records,
    _same_record_value,
    _scope_kind,
    _status,
    _supporting_sources,
    _text,
    _victim_actor_aliases,
    resolve_affected_counts,
    resolve_scalar,
    source_rank,
)

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
            status = _status(raw_record)
            evidence = _text(raw_record.get("evidence"))
            if status in {"negated", "denied", "hypothesis"}:
                continue
            if evidence and (
                _NEGATED_EVIDENCE_RE.search(evidence)
                or _HYPOTHETICAL_EVIDENCE_RE.search(evidence)
            ):
                continue
            if key == "affected_systems" and any(marker in _norm(value) for marker in ("prestataire", "fournisseur", "sous traitant", "tiers")):
                # Un tiers est un contexte de compromission, pas un système de
                # la victime. Il est affiché dans son champ dédié.
                continue
            if key == "affected_datasets" and (
                _looks_like_atomic_data_type(value)
                or _norm(value) in {"donnees personnelles", "informations personnelles"}
            ):
                # Une catégorie atomique appartient à `data_types`, pas aux
                # périmètres. La publier dans les deux zones créait six faux
                # « systèmes » sur Allo E.Leclerc.
                continue
            semantic = _norm(raw_record.get("kind")) or _norm(raw_record.get("scope")) or _norm(value)
            if semantic not in selected:
                selected[semantic] = {
                    "value": value,
                    "status": status,
                    "source": source,
                    "sources": [source] if source else [],
                }
            elif source and source not in selected[semantic]["sources"]:
                selected[semantic]["sources"].append(source)
    return _drop_aggregate_duplicates(list(selected.values()))


def _drop_aggregate_duplicates(entries: list[dict]) -> list[dict]:
    """Retire une entrée qui n'est qu'une concaténation d'au moins deux autres
    valeurs déjà listées séparément (ex. systèmes "WordPress", "ERP" *et* un
    3ᵉ chip "WordPress, ERP, base de production" qui répète les deux premiers)."""
    values_norm = [_norm(entry.get("value")) for entry in entries]
    kept = []
    for index, entry in enumerate(entries):
        value_norm = values_norm[index]
        contained = [
            other for other_index, other in enumerate(values_norm)
            if other_index != index and other and other != value_norm and other in value_norm
        ]
        if len(contained) >= 2:
            continue
        kept.append(entry)
    return kept


def _data_types_entries(facts: Iterable[dict]) -> list[dict]:
    """Fusionne `data_types` legacy (liste plate) et rich (`rich_facts.data_types`).

    Traite chaque fait dans l'ordre de priorité des sources, legacy et rich
    ensemble, pour que la priorité s'applique uniformément aux deux formats
    plutôt que de privilégier arbitrairement l'un des deux formats en bloc.
    """
    selected: dict[str, dict] = {}

    def add(
        value: str,
        source: str,
        status: str = "",
        evidence: str = "",
        blocked_values: tuple[str, ...] = (),
    ) -> None:
        # A type mentioned only to say it was *not* exposed is useful in the
        # source-level audit trail, but must never become a public "Données
        # exposées" chip.  Otherwise a denial such as "aucun IBAN identifié"
        # is presented as the exact opposite fact.
        normalized_status = _status({"status": status})
        evidence_norm = _norm(evidence)
        value_norm = _norm(value)
        value_pos = evidence_norm.find(value_norm) if value_norm else -1
        if value_pos >= 0 and re.search(
            r"\b(?:aucun|aucune|pas de|sans)\b.{0,100}$",
            evidence_norm[max(0, value_pos - 120):value_pos],
        ):
            return
        # Une phrase peut confirmer l'incident puis opposer les catégories
        # uniquement revendiquées par l'attaquant (cas TeleCoop). Le statut
        # suit le verbe déclaratif placé avant la catégorie, pas le statut
        # global de l'article.
        if normalized_status == "confirmed" and "revendiqu" in evidence_norm:
            claim_pos = evidence_norm.rfind("revendiqu")
            value_pos = evidence_norm.rfind(value_norm) if value_norm else -1
            if value_pos >= claim_pos >= 0:
                normalized_status = "claimed"
        if normalized_status in {"negated", "denied", "hypothesis"}:
            return
        if evidence and _NEGATED_EVIDENCE_RE.search(evidence):
            return
        if evidence and _HYPOTHETICAL_EVIDENCE_RE.search(evidence):
            return
        if evidence and _NON_EXPOSURE_DATA_CONTEXT_RE.search(evidence):
            return
        if not value or _norm(value) in UNKNOWN_VALUES or len(value) > _MAX_DATA_TYPE_CHARS or _NUMERIC_ONLY_RE.fullmatch(value):
            return
        # Deux sources peuvent décrire le même type sous deux formulations
        # (ex. "adresses e-mail" vs "Adresse email") : les ramener à un même
        # libellé canonique avant déduplication évite un doublon visuel.
        value = canonical_data_type(value)
        key = _norm(value)
        if key and any(key == blocked or key in blocked for blocked in blocked_values):
            return
        entry = selected.get(key)
        if entry is None:
            selected[key] = {
                "value": value,
                "status": normalized_status,
                "source": source,
                "sources": [source] if source else [],
            }
        else:
            if source and source not in entry["sources"]:
                entry["sources"].append(source)
            entry["status"] = _better_status(entry.get("status", ""), normalized_status)

    for fact in _ordered_facts(facts):
        source = _text(fact.get("source"))
        rich = fact.get("rich_facts") if isinstance(fact.get("rich_facts"), dict) else {}
        rich_values = rich.get("data_types") if isinstance(rich, dict) else None
        blocked_values = tuple({
            _norm(" ".join((
                _text(record.get("value")),
                _text(record.get("evidence")),
            )))
            for record in (rich_values if isinstance(rich_values, list) else [])
            if isinstance(record, dict) and (
                _status(record) in {"negated", "denied", "hypothesis"}
                or _NEGATED_EVIDENCE_RE.search(_text(record.get("evidence")))
                or _HYPOTHETICAL_EVIDENCE_RE.search(_text(record.get("evidence")))
            )
        })
        if isinstance(rich_values, list):
            for raw_record in rich_values:
                if isinstance(raw_record, dict):
                    add(
                        _text(raw_record.get("value")), source,
                        _text(raw_record.get("status")),
                        _text(raw_record.get("evidence")),
                        (),
                    )
        legacy = fact.get("data_types")
        if isinstance(legacy, list):
            for raw in legacy:
                # Claim_Status qualifie l'incident, pas chaque catégorie. Le
                # statut précis vient des faits riches lorsqu'ils existent ;
                # un reliquat legacy reste inconnu plutôt que d'être promu
                # artificiellement « confirmé ».
                add(_text(raw), source, "unknown", blocked_values=blocked_values)
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
            if _is_generic_claim_value(value):
                # Un claim réduit à un mot générique ("compromission" seul) ne
                # documente rien de propre à cet incident précis — cas réel
                # constaté sur Déclic Services dans "Autres éléments documentés".
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


_GENERIC_CLAIM_TERMS = {"fuite", "donnees", "publication", "incident", "cyberattaque", "vol", "compromission", "acces", "extraction"}
_CLAIM_VALUE_STOPWORDS = {"de", "des", "du", "la", "le", "les", "d", "un", "une", "et"}


def _is_generic_claim_value(value: str) -> bool:
    """Un claim dont la valeur ne contient aucun mot propre à l'incident
    ("compromission", "fuite de données") ne documente rien de plus que le
    fait même qu'un incident existe : il est filtré. Un seul mot spécifique
    ("compromission d'un compte administrateur via hameçonnage") suffit à
    conserver le claim."""
    words = [word for word in _norm(value).split() if word not in _CLAIM_VALUE_STOPWORDS]
    return bool(words) and all(word in _GENERIC_CLAIM_TERMS for word in words)


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
    if (
        "revendique" in evidence and value and not re.fullmatch(r"\d+", value)
        and 1 <= len(actor_words) <= 2 and not any(word in _GENERIC_CLAIM_TERMS for word in actor_words)
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


# Vocabulaire générique de compromission (pas de nom d'organisation ni de
# système) : sert uniquement à écarter un claim étiqueté "initial_access" par
# erreur (ex. une simple mise en vente de données, cas réel constaté sur
# Solimut) — jamais à deviner un vecteur non documenté.
_ACCESS_VECTOR_MARKERS = re.compile(
    r"phishing|hame[cç]onnage|injection|sqli?\b|zero[- ]?day|identifiants?|"
    r"mots? de passe|credentials?|exploit|vuln[ée]rabilit[ée]|faille|intrusion|"
    r"brute[- ]force|acc[eè]s (?:non autoris|frauduleux)|compte(?:s)? compromis|"
    r"fonction d'export|export",
    re.I,
)
_INITIAL_ACCESS_CONTEXT_ONLY_RE = re.compile(
    r"\b(?:le contexte actuel|indices? (?:qui )?orientent|r[ée]cemment corrig[ée]e?|"
    r"hypoth[èe]se|pourrait|permettrait)\b",
    re.I,
)
_INITIAL_ACCESS_UNCERTAIN_EVIDENCE_RE = re.compile(
    r"\b(?:impossible|difficile)\s+de\s+(?:d[ée]terminer|[ée]tablir|confirmer)\b|"
    r"\b(?:vecteur|point\s+d['’]entr[ée]e|origine|m[ée]thode)\b.{0,100}"
    r"\b(?:inconnu|non\s+(?:communiqu[ée]|[ée]tabli|d[ée]termin[ée]|confirm[ée]))\b",
    re.I,
)


def _initial_access_is_publishable(entry: dict) -> bool:
    value = _norm(entry.get("value"))
    evidence = _text(entry.get("evidence"))
    if _status(entry) in {"negated", "denied", "hypothesis"}:
        return False
    if evidence and (
        _HYPOTHETICAL_EVIDENCE_RE.search(evidence)
        or _INITIAL_ACCESS_CONTEXT_ONLY_RE.search(evidence)
        or _INITIAL_ACCESS_UNCERTAIN_EVIDENCE_RE.search(evidence)
    ):
        return False
    # « exploitation de vulnérabilité » est le scalaire le plus susceptible
    # d'être déduit d'un simple paragraphe de contexte technique. Sans preuve
    # attachée, le champ reste vide plutôt que d'affirmer le vecteur.
    if value == "vulnerability exploitation":
        return bool(evidence and _ACCESS_VECTOR_MARKERS.search(evidence))
    return True

_IMPACT_CONSEQUENCE_RE = re.compile(
    r"\b(?:indisponib|interruption|arr[êe]t|perturb|fraude|usage frauduleux|"
    r"alt[ée]ration|suppression|destruction|perte financi[èe]re|co[uû]t|"
    r"ran[çc]on|activit[ée] ralentie|services? affect[ée]s?)\b",
    re.I,
)
_DATA_ONLY_IMPACT_RE = re.compile(
    r"\b(?:donn[ée]es?|informations?|fichiers?)\b.*\b(?:expos[ée]s?|"
    r"compromis(?:es)?|revendiqu[ée]es?|li[ée]es?|consult[ée]es?|copi[ée]es?|"
    r"consultation|copie|acc[eè]s non autoris[ée])\b|"
    r"\b(?:expos[ée]s?|compromis(?:es)?|revendiqu[ée]es?|li[ée]es?|"
    r"consult[ée]es?|copi[ée]es?|consultation|copie|acc[eè]s non autoris[ée])\b"
    r".*\b(?:donn[ée]es?|informations?|fichiers?)\b",
    re.I,
)


def _impact_is_publishable(value: Any, status: str = "") -> bool:
    text = _text(value)
    if not text or _status({"status": status}) in {"negated", "denied", "hypothesis"}:
        return False
    if _HYPOTHETICAL_EVIDENCE_RE.search(text):
        return False
    if _DATA_ONLY_IMPACT_RE.search(text) and not _IMPACT_CONSEQUENCE_RE.search(text):
        return False
    return True


def _claim_scalar(claims: Iterable[dict], claim_type: str) -> dict | None:
    candidates = [
        claim for claim in claims
        if claim.get("type") == claim_type
        and _known(claim.get("value"))
        and _status(claim) not in {"negated", "denied", "hypothesis"}
        and not _HYPOTHETICAL_EVIDENCE_RE.search(_text(claim.get("evidence")))
    ]
    if claim_type == "actor":
        # Un nom d'acteur doit figurer dans l'extrait de preuve : un modèle ne
        # peut pas propager un autre acteur simplement cité dans l'article.
        candidates = [
            claim for claim in candidates
            if _norm(claim.get("value")) in _norm(claim.get("evidence"))
        ]
    elif claim_type == "initial_access":
        candidates = [
            claim for claim in candidates
            if _ACCESS_VECTOR_MARKERS.search(_text(claim.get("evidence")))
        ]
    elif claim_type == "impact":
        candidates = [
            claim for claim in candidates
            if _impact_is_publishable(claim.get("value"), _status(claim))
        ]
    if not candidates:
        return None
    claim = sorted(candidates, key=lambda row: (source_rank(row.get("source")), _text(row.get("value"))))[0]
    return {
        "value": claim["value"], "source": claim.get("source", ""), "sources": claim.get("sources", []),
        "status": _status(claim),
    }


def _attack_flow_entries(facts: Iterable[dict]) -> list[dict]:
    selected: dict[str, dict] = {}
    for fact in _ordered_facts(facts):
        source = _text(fact.get("source"))
        status = _status({"status": fact.get("claim_status")})
        steps = fact.get("attack_flow")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            action = _text(step.get("action"))
            evidence = _text(step.get("evidence"))
            if not action or not evidence:
                continue
            key = _norm(action)
            if key not in selected:
                selected[key] = {
                    "action": action,
                    "evidence": evidence,
                    "status": status,
                    "source": source,
                    "sources": [source] if source else [],
                }
            elif source and source not in selected[key]["sources"]:
                selected[key]["sources"].append(source)
    return list(selected.values())


def _propagation_alerts(
    facts: list[dict],
    resolved: dict,
    rejected_fields: set[str],
    organisation: str,
) -> list[dict]:
    """Signale un fait publiable qui disparaît avant le contrat de fiche."""
    alerts: list[dict] = []
    fields = resolved.get("fields", {})
    for field in SCALAR_FIELDS:
        if field in rejected_fields or field in fields:
            continue
        if any(_known(fact.get(field)) for fact in facts):
            alerts.append({
                "code": "SOURCE_FACTS_NOT_PROPAGATED",
                "field": field,
                "severity": "warning",
            })

    list_contracts = {
        "attack_flow": "attack_flow",
        "data_types": "data_types",
        "vulnerabilities": "vulnerabilities",
    }
    for raw_field, resolved_field in list_contracts.items():
        if resolved.get(resolved_field):
            continue
        if any(isinstance(fact.get(raw_field), list) and fact.get(raw_field) for fact in facts):
            alerts.append({
                "code": "SOURCE_FACTS_NOT_PROPAGATED",
                "field": raw_field,
                "severity": "warning",
            })

    if not resolved.get("data_types"):
        rich_claims = [
            claim
            for fact in facts
            for claim in ((fact.get("rich_facts") or {}).get("claims", []))
            if isinstance(claim, dict)
            and _norm(claim.get("type")) == "data type"
            and _status(claim) not in {"denied", "negated", "hypothesis"}
        ]
        if rich_claims:
            alerts.append({
                "code": "DATA_TYPES_EMPTY_WITH_PERSONAL_DATA_EVIDENCE",
                "field": "data_types",
                "severity": "warning",
            })

    if organisation and any(
        victim_claims_incident(fact.get("summary"), organisation)
        for fact in facts
    ):
        alerts.append({
            "code": "SUMMARY_FACT_CONTRADICTION",
            "field": "summary",
            "severity": "error",
        })
    return alerts


_MARKDOWN_EMPHASIS_RE = re.compile(r"\*\*(.+?)\*\*|__(.+?)__")


def _strip_markdown_emphasis(text: str) -> str:
    """Retire le gras Markdown (`**...**`/`__...__`) qui a pu fuiter tel quel
    depuis un article source (constaté sur FRENCHBREACHES) — garde le texte,
    jamais la syntaxe d'édition."""
    return _MARKDOWN_EMPHASIS_RE.sub(lambda m: m.group(1) or m.group(2), text)


def _timeline_entries(facts: Iterable[dict]) -> list[dict]:
    selected: dict[tuple[str, str, str], dict] = {}
    for fact in _ordered_facts(facts):
        source = _text(fact.get("source"))
        rich = fact.get("rich_facts") if isinstance(fact.get("rich_facts"), dict) else {}
        for row in rich.get("timeline", []) if isinstance(rich, dict) else []:
            if not isinstance(row, dict):
                continue
            raw_date = _text(row.get("date"))
            date = parse_date(raw_date) or raw_date
            event = _strip_markdown_emphasis(_text(row.get("event")))
            evidence = _strip_markdown_emphasis(_text(row.get("evidence")))
            if not event or not evidence:
                continue
            if re.search(r"\bCVE-\d{4}-\d+\b", event, re.I) and re.search(
                r"\b(?:publication|publi[ée]e?|rendue? publique|divulgu[ée]e?)\b", event, re.I
            ):
                continue
            key = (_norm(date), _norm(event), _norm(evidence))
            if key not in selected:
                selected[key] = {"date": date, "event": event, "status": _status(row), "evidence": evidence, "source": source, "sources": [source] if source else []}
            elif source and source not in selected[key]["sources"]:
                selected[key]["sources"].append(source)
    return _drop_timeline_evidence_duplicates(list(selected.values()))


def _drop_timeline_evidence_duplicates(entries: list[dict]) -> list[dict]:
    """Deux entrées du même jour dont l'evidence de l'une n'est qu'un extrait
    de l'autre décrivent le même fait publié en deux formulations (phrase
    brute vs libellé nettoyé, cas constaté sur Déclic Services et Solimut) —
    ne garder que la formulation la plus concise."""
    kept: list[dict] = []
    for entry in entries:
        merged = False
        for index, existing in enumerate(kept):
            if _norm(entry.get("date")) != _norm(existing.get("date")):
                continue
            evidence_a, evidence_b = _norm(entry.get("evidence")), _norm(existing.get("evidence"))
            if not evidence_a or not evidence_b or (evidence_a not in evidence_b and evidence_b not in evidence_a):
                continue
            if len(entry.get("event", "")) < len(existing.get("event", "")):
                kept[index] = entry
            merged = True
            break
        if not merged:
            kept.append(entry)
    return kept


def _drop_claims_duplicating_timeline(claims: list[dict], timeline: list[dict]) -> list[dict]:
    """Un extracteur peut publier le même fait à la fois comme claim
    `statement` et comme entrée `timeline` (même evidence, parfois tronquée).
    Le fait reste dans la chronologie ; le doublon générique n'apporte rien
    de plus dans "Faits sourcés"."""
    timeline_evidence = [_norm(row.get("evidence")) for row in timeline if row.get("evidence")]
    if not timeline_evidence:
        return claims
    kept = []
    for claim in claims:
        if claim.get("type") == "statement":
            evidence_norm = _norm(claim.get("evidence"))
            if evidence_norm and any(
                evidence_norm == te or evidence_norm in te or te in evidence_norm
                for te in timeline_evidence
            ):
                continue
        kept.append(claim)
    return kept


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
    if organisation and not is_publishable_for_organisation(text, organisation):
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


def _evidence_unique_value_counts(facts: Iterable[dict]) -> list[dict]:
    """Retrouve, dans l'evidence déjà stockée des claims, un décompte de
    valeurs uniques par type de donnée jamais extrait comme fait séparé (ex.
    "14 947 adresses e-mail uniques" cité dans l'evidence d'un autre claim).

    Complète le filet déjà appliqué par le collecteur (extract_unique_value_
    counts, normalize.py) pour les données déjà collectées avant sa mise en
    place — sans dépendre d'une nouvelle collecte.
    """
    rows: list[dict] = []
    for fact in _ordered_facts(facts):
        source = _text(fact.get("source"))
        rich = fact.get("rich_facts") if isinstance(fact.get("rich_facts"), dict) else {}
        seen_evidence: set[str] = set()
        for claim in rich.get("claims", []) if isinstance(rich, dict) else []:
            if not isinstance(claim, dict):
                continue
            evidence = _text(claim.get("evidence"))
            if not evidence or evidence in seen_evidence:
                continue
            seen_evidence.add(evidence)
            for value, unit, raw in extract_unique_value_counts(evidence):
                rows.append({
                    "value": value, "unit": unit, "raw": raw, "semantic": "unspecified",
                    "status": _status(claim), "source": source, "sources": [source] if source else [],
                    "evidence": evidence,
                })
    return rows


def _merge_affected(base: list[dict], extra: list[dict]) -> list[dict]:
    seen = {(_norm(entry.get("unit")), _norm(_record_value(entry))) for entry in base}
    merged = list(base)
    for entry in extra:
        key = (_norm(entry.get("unit")), _norm(_record_value(entry)))
        if key in seen:
            continue
        # Un même extrait peut d'abord être réparé en unité générique
        # `accounts`, puis relu comme décompte spécifique (adresses e-mail,
        # IBAN...). La seconde forme est plus précise et remplace la première
        # au lieu de créer deux puces pour le même nombre.
        specific_unit = _text(entry.get("unit"))
        duplicate_index = next((
            index for index, existing in enumerate(merged)
            if _norm(existing.get("unit")) == "accounts"
            and is_recognized_data_type(specific_unit)
            and _norm(_record_value(existing)) == _norm(_record_value(entry))
            and _norm(existing.get("evidence")) == _norm(entry.get("evidence"))
        ), None)
        if duplicate_index is not None:
            existing = merged[duplicate_index]
            replacement = dict(entry)
            replacement["sources"] = list(dict.fromkeys(
                list(existing.get("sources") or []) + list(entry.get("sources") or [])
            ))
            merged[duplicate_index] = replacement
            seen.discard((_norm(existing.get("unit")), _norm(_record_value(existing))))
            seen.add(key)
            continue
        seen.add(key)
        merged.append(entry)
    return merged


def build_display_summary(resolved: dict, fallback: str = "") -> str:
    # Une carte ne réassemble jamais impact, volumes ou catégories. Ces faits
    # restent dans le détail ; seul le résumé éditorial déjà validé est publié.
    clean_fallback = _text(fallback)
    if is_publishable_summary(clean_fallback):
        return clean_fallback
    return ""


def resolve_incident_facts(facts: Iterable[dict], *, fallback_summary: str = "", organisation: str = "") -> dict:
    ordered = _ordered_facts(facts)
    rejected_fields: set[str] = set()
    victim_aliases = _victim_actor_aliases(ordered, organisation)
    claims = _dedupe_claim_entries(_claim_entries(ordered) + _relation_claim_entries(ordered) + _evidence_claim_entries(ordered))
    claims = [
        claim for claim in claims
        if claim.get("type") != "actor" or all(
            _is_actor_value_valid(claim.get("value"), alias)
            for alias in victim_aliases
        )
    ]
    fields = {field: value for field in SCALAR_FIELDS if (value := resolve_scalar(ordered, field))}
    # Même filet que ci-dessus pour le scalaire principal : resolve_scalar()
    # ne connaît pas l'organisation et ne peut donc pas l'appliquer lui-même.
    # Cas réel : "L'entreprise indique" promu en fields.threat_actor pour
    # Emil Frey France (§ audit 2026-08-25), invisible au filtre des claims
    # ci-dessus qui ne portait que sur claims[], jamais sur fields.
    if "threat_actor" in fields and not all(
        _is_actor_value_valid(fields["threat_actor"]["value"], alias)
        for alias in victim_aliases
    ):
        del fields["threat_actor"]
        rejected_fields.add("threat_actor")
    if "impact" in fields and not _impact_is_publishable(
        fields["impact"].get("value"), fields["impact"].get("status", "")
    ):
        del fields["impact"]
        rejected_fields.add("impact")
    if "initial_access" in fields and not _initial_access_is_publishable(fields["initial_access"]):
        del fields["initial_access"]
        rejected_fields.add("initial_access")
    # Les scalaires explicitement extraits restent prioritaires. Les claims
    # typés constituent uniquement un filet de provenance pour les acteurs et
    # tiers, dont l'absence de projection ne doit plus vider une fiche riche.
    for field, claim_type in (("threat_actor", "actor"), ("third_party", "third_party"), ("initial_access", "initial_access"), ("impact", "impact")):
        fields.setdefault(field, _claim_scalar(claims, claim_type))
    # Un repli de provenance valide peut réparer un ancien scalaire rejeté
    # (ex. « Celle-ci » remplacé par l'acteur nommé Sophia).
    rejected_fields.difference_update(
        field for field, value in fields.items() if value
    )
    timeline = _timeline_entries(ordered)
    claims = _drop_claims_duplicating_timeline(claims, timeline)
    vulnerabilities = resolve_vulnerabilities(ordered, claims)
    if "cvss" in fields and not any(
        row.get("relationship") == "exploited" for row in vulnerabilities
    ):
        del fields["cvss"]
        rejected_fields.add("cvss")
    resolved = {
        "version": 3,
        "fields": {field: value for field, value in fields.items() if value},
        "data_types": _data_types_entries(ordered),
        "vulnerabilities": vulnerabilities,
        "affected": _merge_affected(resolve_affected_counts(ordered), _evidence_unique_value_counts(ordered)),
        "systems": _resolve_rich_entities(ordered, "affected_systems"),
        "datasets": _resolve_rich_entities(ordered, "affected_datasets"),
        "claims": claims,
        "timeline": timeline,
        "attack_flow": _attack_flow_entries(ordered),
    }
    # Les claims sont déjà publiés dans chaque fait source. Ils servent ici à
    # composer la synthèse canonique sans dupliquer tout leur détail dans la
    # vue résolue par incident.
    resolved["display_summary"] = build_display_summary(
        resolved, fallback=fallback_summary
    )
    resolved["quality_alerts"] = _propagation_alerts(
        ordered, resolved, rejected_fields, organisation
    )
    resolved["rejected_fields"] = sorted(rejected_fields)
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
