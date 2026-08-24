"""Faits supplémentaires publiés par chaque source.

Couche auxiliaire et non canonique : elle ne modifie jamais Threat/Sector/Location.
Pour FrenchBreaches et Cyberattaque.org, le LLM comprend le récit puis cette
couche valide mécaniquement les faits candidats. Les autres sources restent
strictement déterministes/structurées.
"""
from __future__ import annotations

import json
import logging
import re

from . import config, source_facts_ai
from .headline import is_organisation_name_only, is_publishable_headline, rejection_reason
from .collectors.base import RawEntry, SourceSpec
from .model import SOURCE_FACT_COLUMNS, Item
from .normalize import (
    clean_organisation,
    extract_activity_description,
    organisation_key,
    parse_date,
    searchable,
    strip_accents,
)

logger = logging.getLogger(__name__)

SOURCE_FACTS_VERSION = "4"

_BASE_COLUMNS = {
    "Item_ID", "Source_ID", "Extraction_Method", "Extraction_Version",
    "Source_Metadata_JSON", "Evidence_JSON",
}


def _dumps_json(value) -> str:
    if not value:
        return ""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _loads_json(raw: str):
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_CVSS_RE = re.compile(
    r"\bCVSS[:\s]*(?:score\s*)?(?:de\s*)?(\d{1,2}(?:[.,]\d)?)(?:\s*/\s*10)?\b",
    re.I,
)
_VOLUME_RE = re.compile(r"\b\d[\d\s ,.]*\s*(?:Ko|Mo|Go|To|KB|MB|GB|TB)\b", re.I)
_FILE_COUNT_RE = re.compile(r"\b(\d[\d\s .,]*)\s*(?:fichiers?|documents?)\b", re.I)


def _extract_cves(*texts: str) -> list[str]:
    return sorted({match.upper() for text in texts for match in _CVE_RE.findall(text or "")})


def _extract_cvss(*texts: str) -> str:
    for text in texts:
        match = _CVSS_RE.search(text or "")
        if match:
            return match.group(0).strip()
    return ""


def _extract_volume(*texts: str) -> str:
    for text in texts:
        match = _VOLUME_RE.search(text or "")
        if match:
            return match.group(0).strip()
    return ""


def _digits(raw: str) -> str:
    cleaned = (raw or "").replace(" ", "").replace(" ", "").replace(".", "").replace(",", "")
    return cleaned if cleaned.isdigit() else ""


def _extract_file_count(*texts: str) -> str:
    for text in texts:
        match = _FILE_COUNT_RE.search(text or "")
        if match:
            return _digits(match.group(1))
    return ""


def _split_list(text: str) -> list[str]:
    parts = re.split(r",|\bet\b", text or "")
    return [part.strip(" .") for part in parts if part.strip(" .")]


_UNIT_MAP = {
    "personne": "people", "personnes": "people",
    "victime": "people", "victimes": "people",
    "membre": "people", "membres": "people",
    "agent": "people", "agents": "people",
    "compte": "accounts", "comptes": "accounts",
    "utilisateur": "users", "utilisateurs": "users",
    "client": "clients", "clients": "clients",
    "employe": "people", "employes": "people",
    "salarie": "people", "salaries": "people",
    "patient": "people", "patients": "people",
    "eleve": "people", "eleves": "people",
    "abonne": "people", "abonnes": "people",
    "enregistrement": "records", "enregistrements": "records",
    "ligne": "records", "lignes": "records",
    "dossier": "files", "dossiers": "files",
    "fichier": "files", "fichiers": "files",
}

_COUNT_RE = re.compile(
    r"(?:environ\s+|plus\s+de\s+|pr[eè]s\s+de\s+|jusqu['’]?[àa]\s+)?"
    r"(?P<number>\d[\d\s .,]*\d|\d)\s*"
    r"(?P<scale>million[s]?|millier[s]?|mille)?\s*"
    r"(?:de\s+|d['’])?\s*"
    r"(?P<unit>[a-zàâäéèêëïîôöùûüç]+)",
    re.I,
)


def _to_number(raw_number: str, scale: str) -> int | None:
    cleaned = raw_number.replace(" ", "").replace(" ", "").strip()
    scale = (scale or "").lower()
    try:
        if scale.startswith("million"):
            return int(round(float(cleaned.replace(",", ".")) * 1_000_000))
        if scale.startswith(("millier", "mille")):
            return int(round(float(cleaned.replace(",", ".")) * 1_000))
        return int(cleaned.replace(".", "").replace(",", ""))
    except ValueError:
        return None


def _parse_count_phrase(text: str) -> tuple[str, str, str]:
    """Retourne le premier comptage dont l'unité appartient au vocabulaire fermé."""
    if not text:
        return "", "", ""
    for match in _COUNT_RE.finditer(text):
        unit_word = strip_accents(match.group("unit") or "").lower().rstrip(".,;:")
        canonical_unit = _UNIT_MAP.get(unit_word, "")
        if not canonical_unit:
            continue
        number = _to_number(match.group("number"), match.group("scale") or "")
        if number is not None:
            return str(number), canonical_unit, match.group(0).strip()
    return "", "", ""


def _clean_span(raw: str) -> str:
    return clean_organisation(raw).rstrip(" .,;:")


def _normalise_url(value: str) -> str:
    value = (value or "").strip()
    if value and not value.startswith(("http://", "https://")) and "." in value:
        return f"https://{value}"
    return value


_ACTOR_SENTINELS = {
    "", "un", "une", "le", "la", "les", "hacker", "le hacker", "un hacker",
    "attaquant", "l attaquant", "l'attaquant", "auteur", "inconnu", "non identifie",
    "non identifie publiquement", "n a", "na", "n/a",
    "ransomware", "rancongiciel", "cybercriminel", "cybercriminels", "pirate", "pirates",
}


def _valid_actor(candidate: str, organisation: str = "") -> str:
    candidate = _clean_span(candidate)
    normalized = searchable(candidate)
    if not candidate or normalized in _ACTOR_SENTINELS:
        return ""
    if normalized.startswith(("le hacker", "un hacker", "l attaquant", "un attaquant")):
        return ""
    if organisation and organisation_key(candidate) == organisation_key(organisation):
        return ""
    return candidate


def _valid_third_party(candidate: str, organisation: str = "") -> str:
    candidate = _clean_span(candidate)
    normalized = searchable(candidate)
    if not candidate or normalized in {"un", "une", "le", "la", "les", "inconnu"}:
        return ""
    if organisation and organisation_key(candidate) == organisation_key(organisation):
        return ""
    return candidate


_ACTIVITY_BRIDGES = {
    "", "est", "est un", "est une", "est un acteur", "est une entreprise",
    "est une societe", "est un groupe", "est une association", "est un organisme",
    "est une plateforme",
}


def _extract_victim_activity(organisation: str, *texts: str) -> str:
    org = searchable(organisation)
    if not org:
        return ""
    for text in texts:
        for segment in re.split(r"(?<=[.!?;])\s+|\n+", text or ""):
            segment_norm = searchable(segment)
            org_pos = segment_norm.find(org)
            if org_pos < 0:
                continue
            activity = extract_activity_description(segment)
            if not activity:
                continue
            activity_norm = searchable(activity)
            activity_pos = segment_norm.find(activity_norm)
            if activity_pos < org_pos + len(org):
                continue
            bridge = segment_norm[org_pos + len(org):activity_pos].strip(" ,-:()")
            if bridge in _ACTIVITY_BRIDGES:
                return activity
    return ""


def _ai_activity(ai_result: dict, organisation: str) -> tuple[str, str]:
    candidate = ai_result.get("activity_description") if isinstance(ai_result, dict) else None
    if not isinstance(candidate, dict):
        return "", ""
    value = str(candidate.get("value") or "").strip()
    evidence = str(candidate.get("evidence") or "").strip()
    if not value or not evidence or searchable(organisation) not in searchable(evidence):
        return "", ""
    return value, evidence


def _ai_text(ai_result: dict, key: str) -> tuple[str, str]:
    candidate = ai_result.get(key) if isinstance(ai_result, dict) else None
    if not isinstance(candidate, dict):
        return "", ""
    return str(candidate.get("value") or "").strip(), str(candidate.get("evidence") or "").strip()


def _ai_threat_candidate(ai_result: dict) -> dict | None:
    value, evidence = _ai_text(ai_result, "threat_candidate")
    if value not in config.THREATS or value == config.THREAT_UNKNOWN or not evidence:
        return None
    candidate = ai_result.get("threat_candidate") or {}
    return {"value": value, "evidence": evidence, "confidence": candidate.get("confidence", "")}


_STATUS_PRIORITY = {"confirmed": 4, "reported": 3, "claimed": 2, "unknown": 1}


def _ordered_ai_evidence(ai_result: dict, key: str) -> list[dict]:
    values = ai_result.get(key) if isinstance(ai_result, dict) else None
    if not isinstance(values, list):
        return []
    return sorted(
        (value for value in values if isinstance(value, dict)),
        key=lambda value: (
            _STATUS_PRIORITY.get(str(value.get("status") or "unknown"), 0),
            float(value.get("confidence") or 0),
        ),
        reverse=True,
    )


def _ai_count(ai_result: dict) -> tuple[str, str, str, str]:
    for candidate in _ordered_ai_evidence(ai_result, "affected_counts"):
        evidence = str(candidate.get("evidence") or "").strip()
        count, unit, raw = _parse_count_phrase(evidence)
        if count:
            return count, unit, raw, str(candidate.get("status") or "unknown")
    return "", "", "", ""


def _ai_volume(ai_result: dict) -> tuple[str, str]:
    for candidate in _ordered_ai_evidence(ai_result, "data_volumes"):
        evidence = str(candidate.get("evidence") or "").strip()
        value = _extract_volume(evidence)
        if value:
            return value, evidence
    return "", ""


def _ai_file_count(ai_result: dict) -> tuple[str, str]:
    for candidate in _ordered_ai_evidence(ai_result, "file_counts"):
        evidence = str(candidate.get("evidence") or "").strip()
        value = _extract_file_count(evidence)
        if value:
            return value, evidence
    return "", ""


def _ai_data_types(ai_result: dict) -> tuple[list[str], dict[str, str]]:
    values = ai_result.get("data_types") if isinstance(ai_result, dict) else None
    if not isinstance(values, list):
        return [], {}
    result: list[str] = []
    evidence: dict[str, str] = {}
    seen = set()
    for candidate in values:
        if not isinstance(candidate, dict):
            continue
        value = str(candidate.get("value") or "").strip(" .")
        proof = str(candidate.get("evidence") or "").strip()
        key = searchable(value)
        if not value or not proof or key in seen:
            continue
        seen.add(key)
        result.append(value)
        evidence[value] = proof
    return result, evidence


def _ai_initial_access(ai_result: dict) -> tuple[str, str]:
    value, evidence = _ai_text(ai_result, "initial_access")
    if value not in source_facts_ai.INITIAL_ACCESS_VALUES or not evidence:
        return "", ""
    return value, evidence


def _ai_attack_flow(ai_result: dict) -> tuple[list[dict], list[str]]:
    values = ai_result.get("attack_flow") if isinstance(ai_result, dict) else None
    if not isinstance(values, list):
        return [], []
    result: list[dict] = []
    evidence: list[str] = []
    seen = set()
    for candidate in values[:source_facts_ai.MAX_ATTACK_FLOW_STEPS]:
        if not isinstance(candidate, dict):
            continue
        action = str(candidate.get("action") or "").strip()
        proof = str(candidate.get("evidence") or "").strip()
        key = searchable(action)
        if not action or not proof or not key or key in seen:
            continue
        seen.add(key)
        result.append({"action": action, "evidence": proof})
        evidence.append(proof)
    return result, evidence


def _blank_fact(item: Item, spec: SourceSpec) -> dict:
    fact = {col: "" for col in SOURCE_FACT_COLUMNS}
    fact["Item_ID"] = item.Item_ID
    fact["Source_ID"] = item.Source_ID
    fact["Extraction_Method"] = spec.source_id
    fact["Extraction_Version"] = SOURCE_FACTS_VERSION
    return fact


def _has_content(fact: dict) -> bool:
    return any(fact.get(col) for col in SOURCE_FACT_COLUMNS if col not in _BASE_COLUMNS) or bool(fact.get("_Rich_Facts"))


def _finalize(fact: dict, item: Item, entry: RawEntry, evidence: dict) -> dict | None:
    if not _has_content(fact):
        return None
    fact["Evidence_JSON"] = _dumps_json(evidence)
    semantic_status = fact.pop("_Semantic_Refresh_Status", None)
    metadata = dict(entry.source_metadata or {})
    threat_tentative = fact.pop("_Threat_Tentative", None)
    if isinstance(threat_tentative, dict):
        metadata["threat_tentative"] = threat_tentative
    semantic_rich = fact.pop("_Rich_Facts", None)
    if isinstance(semantic_rich, dict) and semantic_rich:
        existing_rich = metadata.get("rich_facts") if isinstance(metadata.get("rich_facts"), dict) else {}
        merged_rich = dict(existing_rich)
        for key, values in semantic_rich.items():
            if not isinstance(values, list):
                continue
            current = merged_rich.get(key) if isinstance(merged_rich.get(key), list) else []
            # The semantic layer is additive: deterministic collector facts
            # remain intact and are never overwritten by an LLM interpretation.
            merged_rich[key] = current + [value for value in values if value not in current]
        metadata["rich_facts"] = merged_rich
    if fact.get("Source_ID") in source_facts_ai.TARGET_SOURCES:
        # Ces marqueurs restent dans le metadata auxiliaire, jamais dans le
        # schéma public SOURCE_FACT_COLUMNS.
        metadata["_source_facts_content_hash"] = source_facts_ai.content_hash(entry)
        if isinstance(semantic_status, dict) and semantic_status:
            metadata["_source_facts_semantic_status"] = semantic_status
        summary = str(fact.get("Summary") or "").strip()
        # Un titre d'article est une headline éditoriale sourcée, à l'inverse
        # des fallbacks construits à partir de volumes ou de vecteurs. Il offre
        # une sortie sûre lorsque le LLM s'abstient, à condition de respecter
        # exactement le même contrat de publication.
        # FrenchBreaches ne renseigne pas systématiquement l'organisation sur
        # RawEntry. L'item a déjà été résolu de manière canonique : c'est lui
        # qui fait autorité pour rejeter un nom seul, y compris au reset zéro.
        organisation = item.Organisation_Raw or entry.organisation or ""
        if not is_publishable_headline(summary) or is_organisation_name_only(summary, organisation):
            # Certains adaptateurs d'hydratation ne réinjectent que le corps
            # dans RawEntry. Le titre canonique est néanmoins conservé sur
            # Item : l'utiliser évite qu'une indisponibilité LLM transforme un
            # article éditorial correctement collecté en synthèse vide.
            title = " ".join(str(entry.title or item.Title or "").split()).strip()
            if is_publishable_headline(title) and not is_organisation_name_only(title, organisation):
                fact["Summary"] = summary = title
                evidence["Summary"] = title
        if is_publishable_headline(summary) and not is_organisation_name_only(summary, organisation):
            metadata["_source_facts_summary_status"] = "accepted"
        else:
            # Une absence éditoriale est explicite : aucun champ structuré ne
            # peut désormais servir de substitut pour une carte.
            fact["Summary"] = ""
            evidence.pop("Summary", None)
            status = (semantic_status or {}).get("summary") if isinstance(semantic_status, dict) else ""
            metadata["_source_facts_summary_status"] = (
                "abstained" if status == "abstained" else "rejected_quality"
            )
            metadata["_source_facts_summary_rejection"] = (
                "organisation_name_only" if is_organisation_name_only(summary, organisation)
                else rejection_reason(summary) or status or "missing"
            )
    if metadata:
        fact["Source_Metadata_JSON"] = _dumps_json(metadata)
    # Les fallbacks éditoriaux peuvent ajouter une preuve après la première
    # sérialisation en tête de fonction.
    fact["Evidence_JSON"] = _dumps_json(evidence)
    return fact


def _apply_blf_summary_certainty(fact: dict) -> None:
    """Évite de présenter une revendication BLF comme un fait confirmé."""
    summary = str(fact.get("Summary") or "").strip()
    status = str(fact.get("Claim_Status") or "").strip()
    if not summary or status == "confirmed":
        return
    replacements = {
        "claimed": (
            ("Données concernées :", "Données revendiquées selon BonjourLaFuite :"),
            ("Éléments documentés :", "Éléments revendiqués selon BonjourLaFuite :"),
        ),
        "unconfirmed": (
            ("Données concernées :", "Données signalées mais non confirmées :"),
            ("Éléments documentés :", "Éléments signalés mais non confirmés :"),
        ),
    }
    for prefix, replacement in replacements.get(status, ()):
        if summary.startswith(prefix):
            fact["Summary"] = replacement + summary[len(prefix):]
            return


_BLF_STATUS = {"🟢": "confirmed", "🟠": "claimed", "🔴": "unconfirmed"}


def _from_bonjourlafuite(item: Item, entry: RawEntry, spec: SourceSpec) -> dict | None:
    fact = _blank_fact(item, spec)
    evidence: dict = {}
    meta = entry.source_metadata or {}

    claim_status_raw = str(meta.get("claim_status_raw") or "").strip()
    if claim_status_raw:
        fact["Claim_Status_Raw"] = claim_status_raw
        fact["Claim_Status"] = _BLF_STATUS.get(claim_status_raw, "")
        evidence["Claim_Status_Raw"] = claim_status_raw

    data_types_raw = str(meta.get("data_types_raw") or "").strip()
    structured = meta.get("data_types")
    data_types: list[str] = []
    if isinstance(structured, list):
        for value in structured:
            cleaned = str(value or "").strip()
            if cleaned and cleaned not in data_types:
                data_types.append(cleaned)
    elif data_types_raw:
        data_types = _split_list(data_types_raw)
    if data_types:
        fact["Data_Types_JSON"] = _dumps_json(data_types)
        evidence["Data_Types_JSON"] = data_types if isinstance(structured, list) else data_types_raw

    count, unit, raw_count = _parse_count_phrase(entry.summary)
    if not count:
        count, unit, raw_count = _parse_count_phrase(data_types_raw or " ; ".join(data_types))
    if count:
        fact["Affected_Count"] = count
        fact["Affected_Unit"] = unit
        fact["Affected_Count_Raw"] = raw_count
        evidence["Affected_Count_Raw"] = raw_count

    _derive_summary(fact, evidence)
    _apply_blf_summary_certainty(fact)

    source_urls = meta.get("source_urls") or []
    if source_urls:
        fact["Evidence_URLs_JSON"] = _dumps_json(source_urls)
    return _finalize(fact, item, entry, evidence)


_CLAIM_STATUS_MAP = (
    (re.compile(r"\bnon\s+confirm[ée]e?\b", re.I), "unconfirmed"),
    (re.compile(r"\bd[ée]menti[e]?\b", re.I), "denied"),
    (re.compile(r"\bconfirm[ée]e?\b", re.I), "confirmed"),
    (re.compile(r"\brevendiqu[ée]e?\b", re.I), "claimed"),
)
_ACTOR_PATTERNS = tuple(re.compile(pattern, re.I) for pattern in (
    r"revendiqu[ée]e?\s+par\s+le\s+groupe\s+([A-Za-z0-9][\w.&'’+-]{1,40})",
    r"\bgroupe\s+([A-Za-z0-9][\w.&'’+-]{1,40})\s+a\s+revendiqu[ée]",
    r"revendiqu[ée]e?\s+par\s+([A-Za-z0-9][\w.&'’+-]{1,40})",
))
_THIRD_PARTY_PATTERNS = tuple(re.compile(pattern, re.I) for pattern in (
    r"\bvia\s+la\s+plateforme\s+([A-Za-z0-9][\w.&'’+-]{1,40})",
    r"\bvia\s+le\s+prestataire\s+([A-Za-z0-9][\w.&'’+-]{1,40})",
    r"\bvia\s+l['’]h[ée]bergeur\s+([A-Za-z0-9][\w.&'’+-]{1,40})",
))


def _claim_status(text: str) -> tuple[str, str]:
    for pattern, canonical in _CLAIM_STATUS_MAP:
        match = pattern.search(text or "")
        if match:
            return canonical, match.group(0)
    return "", ""


def _first_valid_match(patterns, text: str, validator, organisation: str) -> tuple[str, str]:
    for pattern in patterns:
        match = pattern.search(text or "")
        if not match:
            continue
        value = validator(match.group(1), organisation)
        if value:
            return value, match.group(0).strip()
    return "", ""


_FB_SECTOR_RE = re.compile(
    r"\bSecteur\s*[:\-]?\s*([A-Za-zÀ-ÖØ-öø-ÿ/&'’ -]{2,60}?)(?=\s+(?:Fuite|Incident|Qu['’]|Donn[ée]es|Publi[ée]|Victime|Description|Risques?)\b|[.;]|$)",
    re.I,
)


def _native_frenchbreaches_sector(text: str) -> str:
    match = _FB_SECTOR_RE.search(text or "")
    return " ".join(match.group(1).split()).strip(" -:;.") if match else ""


def _apply_semantic_enrichment(fact: dict, evidence: dict, ai_result: dict) -> None:
    initial_access, initial_evidence = _ai_initial_access(ai_result)
    if initial_access:
        fact["Initial_Access"] = initial_access
        evidence["Initial_Access"] = initial_evidence

    attack_flow, flow_evidence = _ai_attack_flow(ai_result)
    if attack_flow:
        fact["Attack_Flow_JSON"] = _dumps_json(attack_flow)
        evidence["Attack_Flow_JSON"] = flow_evidence

    summary, summary_evidence = _ai_text(ai_result, "summary")
    if summary:
        fact["Summary"] = summary
        evidence["Summary"] = summary_evidence

    impact, impact_evidence = _ai_text(ai_result, "impact")
    if impact:
        fact["Impact"] = impact
        evidence["Impact"] = impact_evidence

    for key, column in (("fine_location", "Fine_Location"), ("attack_date", "Attack_Date"), ("discovered_date", "Discovered_Date"), ("evolution", "Evolution")):
        value, proof = _ai_text(ai_result, key)
        if value and not fact.get(column):
            fact[column] = value
            evidence[column] = proof

    vulnerabilities, vulnerability_evidence = _ai_data_types({"data_types": ai_result.get("vulnerabilities", [])})
    if vulnerabilities:
        fact["Vulnerabilities_JSON"] = _dumps_json(vulnerabilities)
        evidence["Vulnerabilities_JSON"] = vulnerability_evidence

    rich: dict[str, list[dict]] = {}
    for key in ("affected_counts", "data_volumes", "file_counts"):
        values = _ordered_ai_evidence(ai_result, key)
        if values:
            rich[key] = values
            evidence[key] = [str(value.get("evidence") or "") for value in values]
    for key in ("affected_systems", "affected_datasets"):
        values = ai_result.get(key) if isinstance(ai_result, dict) else None
        if isinstance(values, list):
            records = [{"value": str(value.get("value") or ""), "status": "confirmed", "evidence": str(value.get("evidence") or "")} for value in values if isinstance(value, dict) and value.get("value")]
            if records:
                rich[key] = records
                evidence[key] = [record["evidence"] for record in records]
    if rich:
        fact["_Rich_Facts"] = rich


def semantic_promotion_gaps(
    fact: dict,
    semantic: source_facts_ai.SemanticExtraction | None,
) -> list[str]:
    """Retourne les champs LLM sourcés qui n'ont pas atteint le fait source.

    Ce contrôle ne devine rien : un champ vide n'est pas un écart. Il protège
    uniquement la frontière cache/SourceFacts/publication contre une perte de
    valeur déjà validée et citée.
    """
    if semantic is None:
        return []
    fields = semantic.fields if isinstance(semantic.fields, dict) else {}
    metadata = _loads_json(str(fact.get("Source_Metadata_JSON") or ""))
    metadata = metadata if isinstance(metadata, dict) else {}
    rich = metadata.get("rich_facts") if isinstance(metadata.get("rich_facts"), dict) else {}
    scalar = {
        "summary": "Summary",
        "initial_access": "Initial_Access",
        "attack_flow": "Attack_Flow_JSON",
        "impact": "Impact",
        "threat_actor": "Threat_Actor",
        "third_party": "Third_Party",
        "fine_location": "Fine_Location",
        "attack_date": "Attack_Date",
        "discovered_date": "Discovered_Date",
        "evolution": "Evolution",
        "vulnerabilities": "Vulnerabilities_JSON",
        "data_types": "Data_Types_JSON",
        "activity_description": "Activity_Description",
    }
    rich_fields = {
        "affected_counts",
        "data_volumes",
        "file_counts",
        "affected_systems",
        "affected_datasets",
    }
    gaps: list[str] = []
    for key, value in fields.items():
        if value in (None, "", [], {}):
            continue
        if key in scalar and not fact.get(scalar[key]):
            gaps.append(key)
        elif key in rich_fields and not rich.get(key):
            gaps.append(key)
        elif key == "threat_candidate" and not metadata.get("threat_tentative"):
            gaps.append(key)
    return sorted(set(gaps))


_INITIAL_ACCESS_LABELS = {
    "phishing": "un hameçonnage",
    "compromised_credentials": "des identifiants compromis",
    "vulnerability_exploitation": "l’exploitation d’une vulnérabilité",
    "remote_access": "un accès distant compromis",
    "third_party": "la compromission d’un tiers",
    "malware": "un logiciel malveillant",
    "other": "un vecteur documenté",
}


def _format_int_fr(value: str) -> str:
    try:
        return f"{int(str(value).strip()):,}".replace(",", " ")
    except (TypeError, ValueError):
        return str(value or "").strip()


def _join_fr(values: list[str]) -> str:
    values = [str(value).strip() for value in values if str(value).strip()]
    if not values:
        return ""
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} et {values[1]}"
    return ", ".join(values[:-1]) + f" et {values[-1]}"


def _evidence_values(value) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, dict):
        return [str(item).strip() for item in value.values() if str(item).strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _structured_summary(fact: dict, evidence: dict) -> tuple[str, list[str]]:
    details: list[str] = []
    proofs: list[str] = []

    volume = str(fact.get("Data_Volume_Raw") or "").strip()
    if volume:
        details.append(f"{volume} de données")
        proofs.extend(_evidence_values(evidence.get("Data_Volume_Raw")) or [volume])

    affected_raw = str(fact.get("Affected_Count_Raw") or "").strip()
    affected_unit = str(fact.get("Affected_Unit") or "").strip()
    if affected_raw:
        details.append(affected_raw)
        proofs.extend(_evidence_values(evidence.get("Affected_Count_Raw")) or [affected_raw])

    file_count = str(fact.get("File_Count") or "").strip()
    if file_count and affected_unit != "files":
        details.append(f"{_format_int_fr(file_count)} fichiers")
        proofs.extend(_evidence_values(evidence.get("File_Count")))

    data_types = _loads_json(str(fact.get("Data_Types_JSON") or ""))
    if not isinstance(data_types, list):
        data_types = []
    data_types = [str(value).strip() for value in data_types if str(value).strip()][:3]
    if data_types:
        proofs.extend(_evidence_values(evidence.get("Data_Types_JSON")))

    # Un seul type de donnée sans volume ni comptage est trop pauvre pour
    # justifier une carte de synthèse. On préfère l'abstention à un doublon UI.
    if not details and len(data_types) < 2:
        return "", []

    if details:
        summary = "Éléments documentés : " + _join_fr(details)
        if data_types:
            summary += " ; données concernées : " + _join_fr(data_types)
        summary += "."
    else:
        summary = "Données concernées : " + _join_fr(data_types) + "."
    return summary, proofs


def _derive_summary(fact: dict, evidence: dict) -> None:
    if fact.get("Source_ID") in source_facts_ai.TARGET_SOURCES:
        return
    if str(fact.get("Summary") or "").strip():
        return
    parts: list[str] = []
    proofs: list[str] = []
    initial = str(fact.get("Initial_Access") or "").strip()
    if initial:
        parts.append(f"Vecteur d’entrée documenté : {_INITIAL_ACCESS_LABELS.get(initial, initial)}.")
        proof = evidence.get("Initial_Access")
        if isinstance(proof, str) and proof:
            proofs.append(proof)
    flow = _loads_json(str(fact.get("Attack_Flow_JSON") or ""))
    if isinstance(flow, list) and flow:
        actions = [str(step.get("action") or "").strip() for step in flow if isinstance(step, dict)]
        actions = [action for action in actions if action][:2]
        if actions:
            parts.append("Déroulé documenté : " + " → ".join(actions) + ".")
        flow_proofs = evidence.get("Attack_Flow_JSON") or []
        if isinstance(flow_proofs, str):
            flow_proofs = [flow_proofs]
        if isinstance(flow_proofs, list):
            proofs.extend(str(value).strip() for value in flow_proofs[:2] if str(value).strip())
    impact = str(fact.get("Impact") or "").strip()
    if impact:
        parts.append("Impact documenté : " + impact.rstrip(" .") + ".")
        proof = evidence.get("Impact")
        if isinstance(proof, str) and proof:
            proofs.append(proof)
    if parts:
        summary = " ".join(parts)
    else:
        summary, structured_proofs = _structured_summary(fact, evidence)
        proofs.extend(structured_proofs)
        if not summary:
            return
    if len(summary) > source_facts_ai.MAX_SUMMARY_CHARS:
        summary = summary[:source_facts_ai.MAX_SUMMARY_CHARS - 1].rsplit(" ", 1)[0].rstrip(" ,;:") + "…"
    fact["Summary"] = summary
    if proofs:
        evidence["Summary"] = " | ".join(dict.fromkeys(proofs))[:source_facts_ai.MAX_EVIDENCE_CHARS]


def _from_frenchbreaches(
    item: Item,
    entry: RawEntry,
    spec: SourceSpec,
    *,
    semantic: source_facts_ai.SemanticExtraction | None = None,
) -> dict | None:
    fact = _blank_fact(item, spec)
    evidence: dict = {}
    text = " ".join(part for part in (entry.title, entry.summary, entry.content) if part)
    organisation = entry.organisation or item.Organisation_Raw
    semantic = semantic or source_facts_ai.extract_semantic(item, entry)
    ai_result = semantic.fields
    fact["_Semantic_Refresh_Status"] = semantic.statuses
    candidate = _ai_threat_candidate(ai_result)
    if candidate and item.Threat == config.THREAT_UNKNOWN:
        fact["_Threat_Tentative"] = candidate

    canonical, raw = _claim_status(text)
    if raw:
        fact["Claim_Status"] = canonical
        fact["Claim_Status_Raw"] = raw
        evidence["Claim_Status"] = raw
    else:
        ai_status, ai_status_evidence = _ai_text(ai_result, "claim_status")
        if ai_status in {"confirmed", "claimed", "unconfirmed", "denied"}:
            fact["Claim_Status"] = ai_status
            evidence["Claim_Status"] = ai_status_evidence

    sector_raw = _native_frenchbreaches_sector(entry.content)
    if sector_raw:
        fact["Source_Sector_Raw"] = sector_raw
        evidence["Source_Sector_Raw"] = sector_raw

    native_count = _parse_count_phrase(entry.content)
    if native_count[0]:
        count, unit, raw_count = native_count
        evidence["Affected_Count_Raw"] = raw_count
    else:
        count, unit, raw_count, count_status = _ai_count(ai_result)
        if count:
            evidence["Affected_Count_Raw"] = {"text": raw_count, "status": count_status}
        else:
            count, unit, raw_count = _parse_count_phrase(text)
            if count:
                evidence["Affected_Count_Raw"] = raw_count
    if count:
        fact["Affected_Count"] = count
        fact["Affected_Unit"] = unit
        fact["Affected_Count_Raw"] = raw_count

    volume, volume_evidence = _ai_volume(ai_result)
    if not volume:
        volume = _extract_volume(text)
    if volume:
        fact["Data_Volume_Raw"] = volume
        if volume_evidence:
            evidence["Data_Volume_Raw"] = volume_evidence

    file_count, file_evidence = _ai_file_count(ai_result)
    if not file_count:
        file_count = _extract_file_count(text)
    if file_count:
        fact["File_Count"] = file_count
        if file_evidence:
            evidence["File_Count"] = file_evidence

    actor, actor_evidence = _ai_text(ai_result, "threat_actor")
    actor = _valid_actor(actor, organisation)
    if not actor:
        actor, actor_evidence = _first_valid_match(_ACTOR_PATTERNS, text, _valid_actor, organisation)
    if actor:
        fact["Threat_Actor"] = actor
        evidence["Threat_Actor"] = actor_evidence

    third_party, third_party_evidence = _ai_text(ai_result, "third_party")
    third_party = _valid_third_party(third_party, organisation)
    if not third_party:
        third_party, third_party_evidence = _first_valid_match(
            _THIRD_PARTY_PATTERNS, text, _valid_third_party, organisation
        )
    if third_party:
        fact["Third_Party"] = third_party
        evidence["Third_Party"] = third_party_evidence

    data_types, data_evidence = _ai_data_types(ai_result)
    if data_types:
        fact["Data_Types_JSON"] = _dumps_json(data_types)
        evidence["Data_Types_JSON"] = data_evidence

    _apply_semantic_enrichment(fact, evidence, ai_result)
    _derive_summary(fact, evidence)

    cves = sorted(set(_extract_cves(text)) | set(_loads_json(fact.get("Vulnerabilities_JSON", "")) or []))
    if cves:
        fact["Vulnerabilities_JSON"] = _dumps_json(cves)
        evidence["Vulnerabilities_JSON"] = ", ".join(cves)
    cvss = _extract_cvss(text)
    if cvss:
        fact["CVSS_Raw"] = cvss

    activity, activity_evidence = _ai_activity(ai_result, organisation)
    if not activity:
        activity = _extract_victim_activity(organisation, entry.title, entry.summary, entry.content)
    if activity:
        fact["Activity_Description"] = activity
        if activity_evidence:
            evidence["Activity_Description"] = activity_evidence
    return _finalize(fact, item, entry, evidence)


_CO_THIRD_PARTY_RE = tuple(re.compile(pattern, re.I) for pattern in (
    r"\b(?:le\s+)?prestataire\s+([A-Za-z0-9][\w.&'’ -]{1,40}?)\s+(?:a\s+[ée]t[ée]\s+)?compromis",
    r"\bh[ée]berg[ée]e?\s+(?:par|chez)\s+([A-Za-z0-9][\w.&'’ -]{1,40}?)(?:,|\.|;| qui| également|$)",
    r"\bla\s+plateforme\s+tierce\s+([A-Za-z0-9][\w.&'’ -]{1,40}?)\s+(?:est\s+)?[àa]\s+l['’]origine",
    r"\bfournisseur\s+([A-Za-z0-9][\w.&'’ -]{1,40}?)\s+explicitement\s+impliqu[ée]",
))
_CO_THREAT_ACTOR_RE = tuple(re.compile(pattern, re.I) for pattern in (
    r"\b(?:le\s+)?groupe\s+([A-Za-z0-9][\w.&'’+-]{1,40})\s+a\s+revendiqu[ée]",
    r"revendiqu[ée]e?\s+par\s+(?:le\s+groupe\s+)?([A-Za-z0-9][\w.&'’+-]{1,40})",
))
_WEBSITE_RE = re.compile(
    r"\bsite\s+(?:officiel\s+|web\s+)?(?:de\s+la\s+victime\s+)?[:\s]+"
    r"((?:https?://)?(?:www\.)?[\w-]+\.[a-z]{2,6}(?:/\S*)?)",
    re.I,
)


def _from_cyberattaque_org(
    item: Item,
    entry: RawEntry,
    spec: SourceSpec,
    *,
    semantic: source_facts_ai.SemanticExtraction | None = None,
) -> dict | None:
    fact = _blank_fact(item, spec)
    evidence: dict = {}
    text = " ".join(part for part in (entry.title, entry.summary, entry.content) if part)
    organisation = entry.organisation or item.Organisation_Raw
    semantic = semantic or source_facts_ai.extract_semantic(item, entry)
    ai_result = semantic.fields
    fact["_Semantic_Refresh_Status"] = semantic.statuses
    candidate = _ai_threat_candidate(ai_result)
    if candidate and item.Threat == config.THREAT_UNKNOWN:
        fact["_Threat_Tentative"] = candidate

    actor, actor_evidence = _ai_text(ai_result, "threat_actor")
    actor = _valid_actor(actor, organisation)
    if not actor:
        actor, actor_evidence = _first_valid_match(_CO_THREAT_ACTOR_RE, text, _valid_actor, organisation)
    if actor:
        fact["Threat_Actor"] = actor
        evidence["Threat_Actor"] = actor_evidence

    third_party, third_party_evidence = _ai_text(ai_result, "third_party")
    third_party = _valid_third_party(third_party, organisation)
    if not third_party:
        third_party, third_party_evidence = _first_valid_match(
            _CO_THIRD_PARTY_RE, text, _valid_third_party, organisation
        )
    if third_party:
        fact["Third_Party"] = third_party
        evidence["Third_Party"] = third_party_evidence

    ai_status, ai_status_evidence = _ai_text(ai_result, "claim_status")
    if ai_status in {"confirmed", "claimed", "unconfirmed", "denied"}:
        fact["Claim_Status"] = ai_status
        evidence["Claim_Status"] = ai_status_evidence
    else:
        canonical, raw = _claim_status(text)
        if raw:
            fact["Claim_Status"] = canonical
            fact["Claim_Status_Raw"] = raw

    count, unit, raw_count, count_status = _ai_count(ai_result)
    if not count:
        count, unit, raw_count = _parse_count_phrase(text)
    if count:
        fact["Affected_Count"] = count
        fact["Affected_Unit"] = unit
        fact["Affected_Count_Raw"] = raw_count
        evidence["Affected_Count_Raw"] = (
            {"text": raw_count, "status": count_status} if count_status else raw_count
        )

    volume, volume_evidence = _ai_volume(ai_result)
    if not volume:
        volume = _extract_volume(text)
    if volume:
        fact["Data_Volume_Raw"] = volume
        if volume_evidence:
            evidence["Data_Volume_Raw"] = volume_evidence

    file_count, file_evidence = _ai_file_count(ai_result)
    if not file_count:
        file_count = _extract_file_count(text)
    if file_count:
        fact["File_Count"] = file_count
        if file_evidence:
            evidence["File_Count"] = file_evidence

    data_types, data_evidence = _ai_data_types(ai_result)
    if data_types:
        fact["Data_Types_JSON"] = _dumps_json(data_types)
        evidence["Data_Types_JSON"] = data_evidence

    _apply_semantic_enrichment(fact, evidence, ai_result)
    _derive_summary(fact, evidence)

    cves = sorted(set(_extract_cves(text)) | set(_loads_json(fact.get("Vulnerabilities_JSON", "")) or []))
    if cves:
        fact["Vulnerabilities_JSON"] = _dumps_json(cves)
        evidence["Vulnerabilities_JSON"] = ", ".join(cves)
    cvss = _extract_cvss(text)
    if cvss:
        fact["CVSS_Raw"] = cvss

    website_match = _WEBSITE_RE.search(text)
    if website_match:
        website = _normalise_url(website_match.group(1))
        if website:
            fact["Victim_Website"] = website
            evidence["Victim_Website"] = website_match.group(0).strip()

    activity, activity_evidence = _ai_activity(ai_result, organisation)
    if not activity:
        activity = _extract_victim_activity(organisation, entry.title, entry.summary, entry.content)
    if activity:
        fact["Activity_Description"] = activity
        if activity_evidence:
            evidence["Activity_Description"] = activity_evidence
    return _finalize(fact, item, entry, evidence)


def _from_ransomware_live(item: Item, entry: RawEntry, spec: SourceSpec) -> dict | None:
    fact = _blank_fact(item, spec)
    evidence: dict = {}
    meta = entry.source_metadata or {}

    group = _valid_actor(meta.get("group", ""), entry.organisation or item.Organisation_Raw)
    if group:
        fact["Threat_Actor"] = group
        evidence["Threat_Actor"] = meta.get("group", "")
    sector_raw = meta.get("sector_raw", "")
    if sector_raw:
        fact["Source_Sector_Raw"] = sector_raw
    discovered = parse_date(meta.get("discovered", ""))
    if discovered:
        fact["Discovered_Date"] = discovered
    attackdate = parse_date(meta.get("attackdate", ""))
    if attackdate:
        fact["Attack_Date"] = attackdate
    website = _normalise_url(meta.get("website", ""))
    if website:
        fact["Victim_Website"] = website
    claim_url = _normalise_url(meta.get("claim_url", ""))
    if claim_url:
        fact["Evidence_URLs_JSON"] = _dumps_json([claim_url])
    return _finalize(fact, item, entry, evidence)


def _from_veillellm(item: Item, entry: RawEntry, spec: SourceSpec) -> dict | None:
    fact = _blank_fact(item, spec)
    meta = entry.source_metadata or {}
    if not meta:
        return None
    if meta.get("localisation", ""):
        fact["Fine_Location"] = meta["localisation"]
    actor = _valid_actor(meta.get("acteur", ""), entry.organisation or item.Organisation_Raw)
    if actor:
        fact["Threat_Actor"] = actor
    if meta.get("statut", ""):
        fact["Claim_Status_Raw"] = meta["statut"]
    score = meta.get("score_cyberattaque")
    if score is not None and str(score) != "":
        fact["Cyberattack_Score"] = str(score)
    if meta.get("impact_connu", ""):
        fact["Impact"] = meta["impact_connu"]
    if meta.get("synthese", ""):
        fact["Summary"] = meta["synthese"]
    if meta.get("evolution", ""):
        fact["Evolution"] = meta["evolution"]
    if meta.get("secteur", ""):
        fact["Source_Sector_Raw"] = meta["secteur"]
    if meta.get("sources"):
        fact["Evidence_URLs_JSON"] = _dumps_json(meta["sources"])
    return _finalize(fact, item, entry, {})


_EXTRACTORS = {
    "BONJOURLAFUITE": _from_bonjourlafuite,
    "FRENCHBREACHES": _from_frenchbreaches,
    "CYBERATTAQUE_ORG": _from_cyberattaque_org,
    "RANSOMWARE_LIVE": _from_ransomware_live,
    "VEILLE_LLM": _from_veillellm,
}


def extract_source_fact(
    item: Item,
    entry: RawEntry,
    spec: SourceSpec,
    *,
    semantic: source_facts_ai.SemanticExtraction | None = None,
) -> dict | None:
    """Retourne un fait source ou None. Une erreur auxiliaire ne bloque jamais la collecte."""
    extractor = _EXTRACTORS.get(spec.source_id)
    if extractor is None:
        return None
    try:
        if item.Source_ID in source_facts_ai.TARGET_SOURCES:
            if semantic and (
                semantic.item_id != item.Item_ID
                or semantic.content_hash != source_facts_ai.content_hash(entry)
            ):
                raise ValueError("semantic_extraction_mismatch")
            return extractor(item, entry, spec, semantic=semantic)
        return extractor(item, entry, spec)
    except Exception as exc:
        logger.warning(
            "source_fact_extraction_failed source=%s item=%s error=%s",
            spec.source_id,
            item.Item_ID,
            exc,
        )
        return None


def merge_source_facts(existing: list[dict], incoming: list[dict]) -> list[dict]:
    refreshable = {"Summary", "Initial_Access", "Attack_Flow_JSON", "Impact"}
    base = {"Item_ID", "Source_ID", "Extraction_Method", "Extraction_Version", "Source_Metadata_JSON"}

    ai_field_for_column = {
        "Summary": "summary",
        "Initial_Access": "initial_access",
        "Attack_Flow_JSON": "attack_flow",
        "Impact": "impact",
    }

    def merge_row(old: dict, new: dict) -> dict:
        merged = dict(old)
        old_evidence = _loads_json(str(old.get("Evidence_JSON") or ""))
        new_evidence = _loads_json(str(new.get("Evidence_JSON") or ""))
        evidence = dict(old_evidence) if isinstance(old_evidence, dict) else {}
        old_meta = _loads_json(str(old.get("Source_Metadata_JSON") or ""))
        new_meta = _loads_json(str(new.get("Source_Metadata_JSON") or ""))
        new_meta = new_meta if isinstance(new_meta, dict) else {}
        # Une réhydratation peut ne produire que le hash de contenu. Conserver
        # alors les faits riches déjà extraits plutôt que de les effacer à la
        # faveur du rafraîchissement d'un champ SourceFacts.
        if isinstance(old_meta, dict) and isinstance(new_meta, dict):
            merged_meta = dict(old_meta)
            merged_meta.update(new_meta)
            new = dict(new)
            new["Source_Metadata_JSON"] = _dumps_json(merged_meta)
        old_hash = str(old_meta.get("_source_facts_content_hash") or "") if isinstance(old_meta, dict) else ""
        new_hash = str(new_meta.get("_source_facts_content_hash") or "") if isinstance(new_meta, dict) else ""
        content_changed = bool(old_hash and new_hash and old_hash != new_hash)
        refresh_status = (
            new_meta.get("_source_facts_semantic_status")
            if isinstance(new_meta, dict) else {}
        )
        refresh_status = refresh_status if isinstance(refresh_status, dict) else {}

        def should_clear(column: str) -> bool:
            # Un premier miss peut être une abstention sémantique transitoire ;
            # une panne technique ne modifie pas le cache. On ne retire donc un
            # ancien fait qu'après deux abstentions sémantiques sur un contenu
            # effectivement différent.
            field = ai_field_for_column.get(column, "")
            if column == "Summary" and new_meta.get("_source_facts_summary_status") in {"rejected_quality", "abstained", "technical_failure"}:
                return True
            return (
                content_changed
                and field
                and refresh_status.get(field) == "abstained"
                and new.get(column, "") in (None, "")
            )

        if isinstance(new_evidence, dict):
            for field, proof in new_evidence.items():
                if field in refreshable and new.get(field, "") in (None, ""):
                    if should_clear(field):
                        evidence.pop(field, None)
                    continue
                if field in refreshable:
                    evidence.pop(field, None)
                evidence[field] = proof
        for column in SOURCE_FACT_COLUMNS:
            if column == "Evidence_JSON":
                continue
            value = new.get(column, "")
            if column in refreshable:
                if value not in (None, ""):
                    merged[column] = value
                elif should_clear(column):
                    merged[column] = ""
                    evidence.pop(column, None)
            elif column in base:
                if value not in (None, ""):
                    merged[column] = value
            elif value not in (None, ""):
                merged[column] = value
        merged["Evidence_JSON"] = _dumps_json(evidence)
        return merged

    by_id: dict[str, dict] = {}
    for row in existing:
        item_id = row.get("Item_ID")
        if item_id:
            by_id[item_id] = dict(row)
    for row in incoming:
        item_id = row.get("Item_ID")
        if not item_id:
            continue
        previous = by_id.get(item_id)
        by_id[item_id] = merge_row(previous or {}, row)
    return [by_id[key] for key in sorted(by_id)]
