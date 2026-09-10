"""Préparation du contexte et validation des faits sémantiques.

Toute valeur — proposée par le LLM ou produite déterministement — traverse ces
normalisateurs avant d'exister comme fait. Ils sont isolés du transport et de
l'orchestration pour rester testables sur un simple couple (valeur, contexte).
"""

from __future__ import annotations

import hashlib
import re

from . import article_body, config
from .collectors.base import RawEntry
from .headline import (
    is_organisation_name_only,
    is_publishable_headline,
    strip_markdown_emphasis,
    summary_role_is_supported,
    victim_claims_incident,
)
from .normalize import classify_threat, searchable
from .source_facts_ai_contract import (
    CONFIDENCE_THRESHOLD,
    INITIAL_ACCESS_VALUES,
    MAX_EVIDENCE_CHARS,
    MAX_LABEL_VALUE_CHARS,
    MAX_INCIDENT_SUMMARY_PARAGRAPH_CHARS,
    _DATA_TYPE_PATTERNS,
    _HYPOTHETICAL_RE,
    _INITIAL_ACCESS_CAUSAL_RE,
    _INITIAL_ACCESS_EVENT_RE,
    _INITIAL_ACCESS_UNCERTAIN_RE,
    _INITIAL_ACCESS_UNKNOWN_RE,
    _NEGATED_DATA_VALUE_PREFIX,
    _RESPONSE_ACTION_RE,
)


def _captured_context(entry: RawEntry) -> str:
    """Texte exact tel que la collecte l'a capturé, navigation comprise."""
    return "\n\n".join(part.strip() for part in (entry.title, entry.summary, entry.content) if (part or "").strip())


def prepared_context(entry: RawEntry) -> article_body.PreparedContext:
    """Contexte capturé et contexte préparé, avec empreintes et retraits."""
    return article_body.prepare_entry(entry)


def _full_context(entry: RawEntry) -> str:
    """Contexte réellement soumis à l'extraction : le corps principal seul.

    Les articles connexes et les ressources de bas de page ne décrivent pas
    l'incident de cette victime. Les laisser dans le contexte revenait à
    publier « fuite de données » sur un article qui écarte explicitement cette
    menace (Le Tampon, 09/09/2026) et à imputer à Citadium la CVE d'un article
    Shipup recopié au-dessus du corps réel.
    """
    return article_body.prepare_entry(entry).prepared


def _content_hash(entry: RawEntry) -> str:
    """Empreinte du texte **capturé**, pas du texte préparé.

    Elle identifie une version d'article dans le cache : la faire dépendre des
    règles de préparation invaliderait tout le cache à chaque évolution de
    celles-ci, sans qu'aucune source n'ait changé. La revalidation des valeurs
    caches se fait sur le contexte préparé, champ par champ.
    """
    return hashlib.sha256(_captured_context(entry).encode("utf-8")).hexdigest()


def content_hash(entry: RawEntry) -> str:
    """Empreinte publique de l'entrée utilisée pour la cohérence SourceFacts."""
    return _content_hash(entry)


def _truncate_context(context: str, max_chars: int) -> str:
    if len(context) <= max_chars:
        return context
    head = max_chars * 2 // 3
    tail = max_chars - head
    return context[:head] + "\n[… contenu intermédiaire tronqué …]\n" + context[-tail:]


def _grounded(evidence: str, context: str) -> bool:
    needle = searchable(evidence)
    return bool(needle) and needle in searchable(context)


def _evidence_window(evidence: str, context: str, radius: int = 180) -> str:
    if not evidence or not context:
        return evidence or ""
    pos = context.casefold().find(evidence.casefold())
    if pos < 0:
        return evidence
    return context[max(0, pos - radius): min(len(context), pos + len(evidence) + radius)]


def _evidence_sentence(evidence: str, context: str) -> str:
    """Retourne la phrase source qui contient l'extrait cité par le modèle."""
    if not evidence or not context:
        return evidence or ""
    pos = context.casefold().find(evidence.casefold())
    if pos < 0:
        return evidence
    start = max(context.rfind(".", 0, pos), context.rfind("!", 0, pos), context.rfind("?", 0, pos)) + 1
    ends = [point for point in (context.find(".", pos), context.find("!", pos), context.find("?", pos)) if point >= 0]
    end = min(ends) + 1 if ends else len(context)
    return context[start:end]


def _negated_data_type(value: str, evidence: str, context: str) -> bool:
    """Vérifie qu'une catégorie n'est pas citée hors d'une exposition réelle."""
    sentence = _evidence_sentence(evidence, context)
    if _NON_EXPOSURE_DATA_CONTEXT_RE.search(sentence):
        return True
    value_key = searchable(value)
    for canonical, pattern in _DATA_TYPE_PATTERNS:
        if searchable(canonical) != value_key:
            continue
        for match in pattern.finditer(sentence):
            if _NEGATED_DATA_VALUE_PREFIX.search(sentence[:match.start()]):
                return True
    return False


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


def _valid_confidence(value) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if 0 <= number <= 1 else None


def _normalize_fact(raw, context: str, require_value_in_evidence: bool = False) -> dict | None:
    if not isinstance(raw, dict):
        return None
    value = " ".join(str(raw.get("value") or "").split()).strip()
    evidence = " ".join(str(raw.get("evidence") or "").split()).strip()
    confidence = _valid_confidence(raw.get("confidence"))
    if confidence is None or confidence < CONFIDENCE_THRESHOLD or not value:
        return None
    if not evidence or len(evidence) > MAX_EVIDENCE_CHARS or not _grounded(evidence, context):
        return None
    if require_value_in_evidence and searchable(value) not in searchable(evidence):
        return None
    return {"value": value, "confidence": confidence, "evidence": evidence}


def _normalize_initial_access(raw, context: str) -> dict | None:
    if _INITIAL_ACCESS_UNKNOWN_RE.search(context or "") or _INITIAL_ACCESS_UNCERTAIN_RE.search(context or ""):
        return None
    fact = _normalize_fact(raw, context)
    if not fact or fact["value"] not in INITIAL_ACCESS_VALUES:
        return None
    window = _evidence_window(fact["evidence"], context)
    if (
        _HYPOTHETICAL_RE.search(window)
        or not _INITIAL_ACCESS_EVENT_RE.search(window)
        or not _INITIAL_ACCESS_CAUSAL_RE.search(window)
    ):
        return None
    return fact


def _normalize_impact(raw, context: str) -> dict | None:
    fact = _normalize_fact(raw, context)
    if not fact:
        return None
    fact["value"] = strip_markdown_emphasis(fact["value"])
    window = _evidence_window(fact["evidence"], context)
    combined = f"{fact['value']} {window}"
    if _HYPOTHETICAL_RE.search(combined) or _RESPONSE_ACTION_RE.search(combined):
        return None
    return fact


_HEADLINE_TECHNICAL_RE = re.compile(
    r"\b(?:header\s+html|javascript|css|cookie|lcp|chargement|vitesse\s+d[’']apparition|performance\s+web|navigation|footer|changelog)\b",
    re.I,
)
_HEADLINE_GENERIC_RE = re.compile(
    r"^(?:l[’']incident|la\s+cyberattaque|l[’']attaque|la\s+fuite)\s+(?:a\s+)?(?:entra[iî]n[ée]|provoqu[ée]|caus[ée])\s+(?:une\s+)?(?:exfiltration|fuite)\s+de\s+donn[ée]es\.?$",
    re.I,
)


def _normalize_summary(raw, context: str, organisation: str = "") -> dict | None:
    """Valide une headline lisible pour la carte, jamais un extrait technique."""
    fact = _normalize_fact(raw, context)
    if not fact:
        return None
    # `rejection_reason` rejette tout `**` : sans ce nettoyage, un résidu
    # Markdown de la source faisait perdre un résumé pourtant valide au lieu de
    # le corriger. La preuve, elle, garde sa syntaxe d'origine.
    value = fact["value"] = strip_markdown_emphasis(fact["value"])
    if (
        not is_publishable_headline(value)
        or is_organisation_name_only(value, organisation)
        or not summary_role_is_supported(value, fact["evidence"], organisation)
    ):
        return None
    return fact


_INCIDENT_SUMMARY_GENERIC_RE = re.compile(
    r"^(?:(?:un|cet|cette)\s+(?:cyber[- ]?)?incident|l[’'](?:cyber[- ]?)?incident)\s+"
    r"(?:concernant\s+.{2,80}\s+)?"
    r"(?:a\s+[ée]t[ée]\s+signal[ée]|est\s+survenu|fait\s+l[’']objet\s+d[’']une\s+enqu[êe]te)\.?$|"
    r"^(?:une\s+enqu[êe]te\s+est\s+en\s+cours|des\s+mesures\s+ont\s+[ée]t[ée]\s+prises|"
    r"la\s+situation\s+est\s+suivie)\.?$",
    re.I,
)


def _incident_summary_is_generic(value: str) -> bool:
    return bool(_INCIDENT_SUMMARY_GENERIC_RE.fullmatch(value.strip()))


def _incident_summary_is_duplicate(first: str, second: str) -> bool:
    first_key = searchable(first)
    second_key = searchable(second)
    if not first_key or not second_key:
        return True
    if first_key == second_key or first_key in second_key or second_key in first_key:
        return True
    first_words = set(first_key.split())
    second_words = set(second_key.split())
    return len(first_words & second_words) / max(1, len(first_words | second_words)) >= 0.8


def _normalize_incident_summary_paragraph(
    raw, context: str, organisation: str = ""
) -> dict | None:
    if not isinstance(raw, dict):
        return None
    source_value = str(raw.get("value") or "")
    if (
        "\n" in source_value
        or source_value.lstrip().startswith(("-", "*", "#"))
        or "**" in source_value
    ):
        return None
    fact = _normalize_fact(raw, context)
    if not fact:
        return None
    value = fact["value"] = strip_markdown_emphasis(fact["value"])
    if (
        len(value) > MAX_INCIDENT_SUMMARY_PARAGRAPH_CHARS
        or _HEADLINE_TECHNICAL_RE.search(value)
        or is_organisation_name_only(value, organisation)
        or victim_claims_incident(value, organisation)
        or not summary_role_is_supported(value, fact["evidence"], organisation)
    ):
        return None
    return fact


def _normalize_incident_summary(raw, context: str, organisation: str = "") -> list[dict]:
    """Valide un résumé autonome, puis au plus un complément substantiel."""
    if not isinstance(raw, list) or not raw:
        return []
    first = _normalize_incident_summary_paragraph(raw[0], context, organisation)
    if not first:
        return []
    result = [first]
    if len(raw) < 2 or _incident_summary_is_generic(first["value"]):
        return result
    second = _normalize_incident_summary_paragraph(raw[1], context, organisation)
    if (
        second
        and not _incident_summary_is_generic(second["value"])
        and not _incident_summary_is_duplicate(first["value"], second["value"])
    ):
        result.append(second)
    return result


def _normalize_data_types(raw: dict, context: str) -> list[dict]:
    values: list[dict] = []
    seen: set[str] = set()
    candidates = raw.get("data_types", [])
    for candidate in candidates if isinstance(candidates, list) else []:
        fact = _normalize_fact(candidate, context)
        if not fact or len(fact["value"]) > MAX_LABEL_VALUE_CHARS:
            continue
        if _negated_data_type(fact["value"], fact["evidence"], context):
            continue
        key = searchable(fact["value"])
        if key and key not in seen:
            seen.add(key)
            values.append(fact)
    return values[:20]


def _normalize_record_lists(raw: dict, context: str, fields: set[str]) -> dict:
    """Reconstruit les faits numériques exclusivement depuis leur preuve citée."""
    from . import source_facts as sf

    result: dict = {}
    parsers = (
        ("affected_counts", sf._parse_count_phrase),
    )
    for key, parser in parsers:
        if key not in fields:
            continue
        values = []
        candidates = raw.get(key, [])
        for candidate in candidates if isinstance(candidates, list) else []:
            if not isinstance(candidate, dict):
                continue
            evidence = " ".join(str(candidate.get("evidence") or "").split()).strip()
            confidence = _valid_confidence(candidate.get("confidence"))
            if not evidence or confidence is None or confidence < CONFIDENCE_THRESHOLD:
                continue
            if not _grounded(evidence, context):
                continue
            parsed = parser(evidence)
            common = {
                "scope": str(candidate.get("scope") or "total"),
                "status": str(candidate.get("status") or "confirmed"),
                "confidence": confidence,
                "evidence": evidence,
            }
            if key == "affected_counts":
                value, unit, raw_value = parsed
                if value:
                    values.append({"value": int(value), "unit": unit, "raw": raw_value, **common})
        if values:
            result[key] = values[:20]
    return result


def _normalize(raw: dict, context: str, fields: set[str], organisation: str = "") -> dict:
    result: dict = {}
    if "summary" in fields:
        fact = _normalize_summary(raw.get("summary"), context, organisation)
        if fact:
            result["summary"] = fact
    if "incident_summary" in fields:
        paragraphs = _normalize_incident_summary(
            raw.get("incident_summary"), context, organisation
        )
        if paragraphs:
            result["incident_summary"] = paragraphs
    if "initial_access" in fields:
        fact = _normalize_initial_access(raw.get("initial_access"), context)
        if fact:
            result["initial_access"] = fact
    if "impact" in fields:
        fact = _normalize_impact(raw.get("impact"), context)
        if fact:
            result["impact"] = fact
    for key in ("threat_actor", "third_party"):
        if key in fields:
            fact = _normalize_fact(raw.get(key), context, require_value_in_evidence=True)
            if fact:
                result[key] = fact
    if "data_types" in fields:
        values = _normalize_data_types(raw, context)
        if values:
            result["data_types"] = values
    for key in ("fine_location",):
        if key in fields:
            fact = _normalize_fact(raw.get(key), context)
            if fact:
                result[key] = fact
    if {"activity_description", "activity_sector_match"} & fields:
        from .source_facts_ai_activity import normalize_activity
        activity, _ = normalize_activity(raw, context, organisation)
        result.update(activity)
    if "threat_candidate" in fields:
        fact = _normalize_fact(raw.get("threat_candidate"), context)
        if fact and fact["value"] in config.THREATS and fact["value"] != config.THREAT_UNKNOWN:
            window = _evidence_window(fact["evidence"], context)
            # Une preuve disant seulement « piratage » ne peut pas soutenir
            # Malware (cas réel LebonSiege). Le candidat doit être la menace
            # que le classifieur déterministe relit dans l'extrait exact.
            grounded_threat = classify_threat(fact["evidence"])
            if not _HYPOTHETICAL_RE.search(window) and grounded_threat == fact["value"]:
                result["threat_candidate"] = fact
    for key in ("affected_systems", "affected_datasets"):
        if key in fields:
            values = []
            for candidate in raw.get(key, []) if isinstance(raw.get(key), list) else []:
                fact = _normalize_fact(candidate, context)
                # Do not publish empty catch-all labels as systems/datasets.
                if fact and searchable(fact["value"]) not in {"systeme informatique", "infrastructure informatique", "reseau"}:
                    values.append(fact)
            if values:
                result[key] = values[:20]
    result.update(_normalize_record_lists(raw, context, fields))
    return result
