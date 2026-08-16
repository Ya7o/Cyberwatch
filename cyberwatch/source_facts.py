"""Faits source par article (§13 METHODOLOGY.md).

Couche auxiliaire, strictement offline : elle conserve uniquement des faits
explicitement publiés par la source et ne modifie jamais Threat/Sector/Location.
La précision prime sur le taux de remplissage : une extraction ambiguë reste vide.
"""
from __future__ import annotations

import json
import re

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

SOURCE_FACTS_VERSION = "2"

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
    r"\bCVSS[:\s]*(?:score\s*)?(?:de\s*)?(\d{1,2}(?:\.\d)?)(?:\s*/\s*10)?\b",
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


def _extract_file_count(*texts: str) -> str:
    for text in texts:
        match = _FILE_COUNT_RE.search(text or "")
        if match:
            digits = (
                match.group(1)
                .replace(" ", "")
                .replace(" ", "")
                .replace(".", "")
                .replace(",", "")
            )
            if digits.isdigit():
                return digits
    return ""


def _split_list(text: str) -> list[str]:
    parts = re.split(r",|\bet\b", text or "")
    return [part.strip(" .") for part in parts if part.strip(" .")]


_UNIT_MAP = {
    "personne": "people", "personnes": "people",
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
    r"(?:environ\s+|plus\s+de\s+|pr[eè]s\s+de\s+)?"
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
    """Retourne uniquement un nombre dont l'unité appartient au vocabulaire fermé."""
    if not text:
        return "", "", ""
    match = _COUNT_RE.search(text)
    if not match:
        return "", "", ""
    unit_word = strip_accents(match.group("unit") or "").lower().rstrip(".,;:")
    canonical_unit = _UNIT_MAP.get(unit_word, "")
    if not canonical_unit:
        return "", "", ""
    number = _to_number(match.group("number"), match.group("scale") or "")
    if number is None:
        return "", "", ""
    return str(number), canonical_unit, match.group(0).strip()


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
    "non identifie publiquement", "n a", "na",
    # §stabilisation pré-release : catégories génériques de menace qui ne
    # sont jamais un nom d'acteur — cas réel corrigé, "revendiquée par le
    # groupe Ransomware" produisait Threat_Actor="Ransomware". Un vrai groupe
    # nommé (LockBit, Qilin, Akira...) ne matche jamais ces entrées.
    "ransomware", "rancongiciel", "cybercriminel", "cybercriminels",
    "pirate", "pirates",
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
    "",
    "est",
    "est un",
    "est une",
    "est un acteur",
    "est une entreprise",
    "est une societe",
    "est un groupe",
    "est une association",
    "est un organisme",
    "est une plateforme",
}


def _extract_victim_activity(organisation: str, *texts: str) -> str:
    """Extrait une activité explicitement rattachée à la victime.

    La présence de la victime dans la même phrase ne suffit pas : dans
    ``un forum spécialisé dans les fuites revendique X``, l'activité décrit
    le forum. La victime doit précéder l'expression métier et n'en être séparée
    que par un connecteur fermé (``est``, ``est une entreprise``, ponctuation).
    """
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
            if activity_pos < 0 or activity_pos < org_pos + len(org):
                continue
            bridge = segment_norm[org_pos + len(org):activity_pos].strip(" ,-:()")
            if bridge in _ACTIVITY_BRIDGES:
                return activity
    return ""


def _blank_fact(item: Item, spec: SourceSpec) -> dict:
    fact = {col: "" for col in SOURCE_FACT_COLUMNS}
    fact["Item_ID"] = item.Item_ID
    fact["Source_ID"] = item.Source_ID
    fact["Extraction_Method"] = spec.source_id
    fact["Extraction_Version"] = SOURCE_FACTS_VERSION
    return fact


def _has_content(fact: dict) -> bool:
    return any(fact.get(col) for col in SOURCE_FACT_COLUMNS if col not in _BASE_COLUMNS)


def _finalize(fact: dict, entry: RawEntry, evidence: dict) -> dict | None:
    if not _has_content(fact):
        return None
    fact["Evidence_JSON"] = _dumps_json(evidence)
    if entry.source_metadata:
        fact["Source_Metadata_JSON"] = _dumps_json(entry.source_metadata)
    return fact


def _from_bonjourlafuite(item: Item, entry: RawEntry, spec: SourceSpec) -> dict | None:
    fact = _blank_fact(item, spec)
    evidence: dict = {}
    meta = entry.source_metadata or {}

    claim_status_raw = meta.get("claim_status_raw", "")
    if claim_status_raw:
        fact["Claim_Status_Raw"] = claim_status_raw
        evidence["Claim_Status_Raw"] = claim_status_raw

    # "Via" est une provenance brute, pas une preuve suffisante d'implication
    # d'un tiers. Elle reste dans Source_Metadata_JSON sans peupler Third_Party.
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
        # Quand le collecteur fournit les bulles structurées, on conserve
        # cette liste comme preuve afin qu'une virgule ou « et » interne à un
        # libellé ne soit jamais interprété comme un séparateur.
        evidence["Data_Types_JSON"] = data_types if isinstance(structured, list) else data_types_raw

    count_text = data_types_raw or " ; ".join(data_types) or entry.summary
    count, unit, raw_count = _parse_count_phrase(count_text)
    if count:
        fact["Affected_Count"] = count
        fact["Affected_Unit"] = unit
        fact["Affected_Count_Raw"] = raw_count
        evidence["Affected_Count_Raw"] = raw_count

    source_urls = meta.get("source_urls") or []
    if source_urls:
        fact["Evidence_URLs_JSON"] = _dumps_json(source_urls)
    return _finalize(fact, entry, evidence)


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


def _from_frenchbreaches(item: Item, entry: RawEntry, spec: SourceSpec) -> dict | None:
    fact = _blank_fact(item, spec)
    evidence: dict = {}
    text = f"{entry.title} {entry.summary}"
    organisation = entry.organisation or item.Organisation_Raw

    canonical, raw = _claim_status(text)
    if raw:
        fact["Claim_Status"] = canonical
        fact["Claim_Status_Raw"] = raw

    count, unit, raw_count = _parse_count_phrase(text)
    if count:
        fact["Affected_Count"] = count
        fact["Affected_Unit"] = unit
        fact["Affected_Count_Raw"] = raw_count
        evidence["Affected_Count_Raw"] = raw_count

    volume = _extract_volume(text)
    if volume:
        fact["Data_Volume_Raw"] = volume
    file_count = _extract_file_count(text)
    if file_count:
        fact["File_Count"] = file_count

    actor, actor_evidence = _first_valid_match(
        _ACTOR_PATTERNS, text, _valid_actor, organisation
    )
    if actor:
        fact["Threat_Actor"] = actor
        evidence["Threat_Actor"] = actor_evidence

    third_party, third_party_evidence = _first_valid_match(
        _THIRD_PARTY_PATTERNS, text, _valid_third_party, organisation
    )
    if third_party:
        fact["Third_Party"] = third_party
        evidence["Third_Party"] = third_party_evidence

    cves = _extract_cves(text)
    if cves:
        fact["Vulnerabilities_JSON"] = _dumps_json(cves)
        evidence["Vulnerabilities_JSON"] = ", ".join(cves)
    cvss = _extract_cvss(text)
    if cvss:
        fact["CVSS_Raw"] = cvss

    activity = _extract_victim_activity(organisation, entry.title, entry.summary)
    if activity:
        fact["Activity_Description"] = activity
    return _finalize(fact, entry, evidence)


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


def _from_cyberattaque_org(item: Item, entry: RawEntry, spec: SourceSpec) -> dict | None:
    fact = _blank_fact(item, spec)
    evidence: dict = {}
    text = f"{entry.title} {entry.summary} {entry.content}"
    organisation = entry.organisation or item.Organisation_Raw

    third_party, third_party_evidence = _first_valid_match(
        _CO_THIRD_PARTY_RE, text, _valid_third_party, organisation
    )
    if third_party:
        fact["Third_Party"] = third_party
        evidence["Third_Party"] = third_party_evidence

    actor, actor_evidence = _first_valid_match(
        _CO_THREAT_ACTOR_RE, text, _valid_actor, organisation
    )
    if actor:
        fact["Threat_Actor"] = actor
        evidence["Threat_Actor"] = actor_evidence

    count, unit, raw_count = _parse_count_phrase(text)
    if count:
        fact["Affected_Count"] = count
        fact["Affected_Unit"] = unit
        fact["Affected_Count_Raw"] = raw_count
        evidence["Affected_Count_Raw"] = raw_count

    volume = _extract_volume(text)
    if volume:
        fact["Data_Volume_Raw"] = volume
    file_count = _extract_file_count(text)
    if file_count:
        fact["File_Count"] = file_count
    cves = _extract_cves(text)
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

    activity = _extract_victim_activity(
        organisation, entry.title, entry.summary, entry.content
    )
    if activity:
        fact["Activity_Description"] = activity
    return _finalize(fact, entry, evidence)


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
    return _finalize(fact, entry, evidence)


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

    return _finalize(fact, entry, {})


_EXTRACTORS = {
    "BONJOURLAFUITE": _from_bonjourlafuite,
    "FRENCHBREACHES": _from_frenchbreaches,
    "CYBERATTAQUE_ORG": _from_cyberattaque_org,
    "RANSOMWARE_LIVE": _from_ransomware_live,
    "VEILLE_LLM": _from_veillellm,
}


def extract_source_fact(item: Item, entry: RawEntry, spec: SourceSpec) -> dict | None:
    """Retourne un fait source ou None. Une erreur auxiliaire ne bloque jamais la collecte."""
    extractor = _EXTRACTORS.get(spec.source_id)
    if extractor is None:
        return None
    try:
        return extractor(item, entry, spec)
    except Exception:
        return None


def merge_source_facts(existing: list[dict], incoming: list[dict]) -> list[dict]:
    by_id: dict[str, dict] = {}
    for row in existing:
        item_id = row.get("Item_ID")
        if item_id:
            by_id[item_id] = row
    for row in incoming:
        item_id = row.get("Item_ID")
        if item_id:
            by_id[item_id] = row
    return [by_id[key] for key in sorted(by_id)]