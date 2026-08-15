"""Faits source par article (§13 METHODOLOGY.md).

Un fait source décrit ce qu'une source publie explicitement pour un item —
jamais une connaissance canonique sur l'organisation. `Threat`/`Sector`/
`Location` (qualification canonique, `Item`) n'en dépendent jamais et cette
couche ne les modifie jamais.

Extraction strictement offline : aucun accès réseau, aucun appel OpenAI,
aucune recherche Web. Politique en 4 niveaux de confiance, du plus sûr au
plus prudent :
  1. champ structuré transmis directement par la source (`entry.source_metadata`
     ou champs déjà structurés de `RawEntry` comme `organisation`/`sector`) ;
  2. structure syntaxique explicite propre à la source ("Via X",
     "Données concernées : ...", "CVE-AAAA-NNNNN") ;
  3. extraction déterministe prudente depuis `summary`/`content`, vocabulaire
     fermé (unités, verbes de compromission explicites) ;
  4. sinon : champ vide. Jamais de déduction à partir d'une connaissance
     externe, jamais de valeur "probable" — la précision prime sur le taux
     de remplissage.
"""

from __future__ import annotations

import json
import re

from .collectors.base import RawEntry, SourceSpec
from .model import SOURCE_FACT_COLUMNS, Item
from .normalize import clean_organisation, parse_date, strip_accents

#: Bump uniquement si les règles d'extraction changent matériellement
#: (même esprit que `config.METHOD_ID`, mais scope local à ce module —
#: `source_facts.csv` n'entre dans aucun hash canonique).
SOURCE_FACTS_VERSION = "1"

_BASE_COLUMNS = {
    "Item_ID", "Source_ID", "Extraction_Method", "Extraction_Version",
    "Source_Metadata_JSON", "Evidence_JSON",
}


# --------------------------------------------------------------------------
# JSON déterministe
# --------------------------------------------------------------------------


def _dumps_json(value) -> str:
    """Sérialisation JSON canonique, `""` pour une valeur vide (convention
    CSV existante : cellule vide = absence)."""
    if not value:
        return ""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _loads_json(raw: str):
    """Inverse tolérant de `_dumps_json` : `None` sur chaîne vide ou JSON
    invalide (jamais d'exception, réservé aux tests de round-trip)."""
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------
# Motifs communs à plusieurs sources
# --------------------------------------------------------------------------

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_CVSS_RE = re.compile(r"\bCVSS[:\s]*(?:score\s*)?(?:de\s*)?(\d{1,2}(?:\.\d)?)(?:\s*/\s*10)?\b", re.I)
_VOLUME_RE = re.compile(r"\b\d[\d\s ,.]*\s*(?:Ko|Mo|Go|To|KB|MB|GB|TB)\b", re.I)
_FILE_COUNT_RE = re.compile(r"\b(\d[\d\s .,]*)\s*(?:fichiers?|documents?)\b", re.I)
_ACTIVITY_RE = re.compile(
    r"\b(?:sp[ée]cialis[ée]e?\s+dans|[ée]diteur\s+de|acteur\s+de)\s+([^,.;:\n]{3,80})",
    re.I,
)


def _extract_cves(*texts: str) -> list[str]:
    found = {match.upper() for text in texts for match in _CVE_RE.findall(text or "")}
    return sorted(found)


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
            digits = match.group(1).replace(" ", "").replace(" ", "").replace(".", "").replace(",", "")
            if digits.isdigit():
                return digits
    return ""


def _activity_description(*texts: str) -> str:
    for text in texts:
        match = _ACTIVITY_RE.search(text or "")
        if match:
            return match.group(0).strip()
    return ""


def _split_list(text: str) -> list[str]:
    """Découpe une énumération française ("noms, emails et mots de passe")
    en éléments distincts, sans autre interprétation."""
    parts = re.split(r",|\bet\b", text or "")
    return [part.strip(" .") for part in parts if part.strip(" .")]


#: Vocabulaire fermé et conservateur : sans correspondance, `Affected_Count`/
#: `Affected_Unit` restent vides même si un nombre est détecté (§13 — mieux
#: vaut ne rien affirmer qu'inventer une unité).
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
    re.IGNORECASE,
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
    """Nombre + unité explicites, ou `("", "", "")` si rien de fiable.

    `raw` (troisième élément) conserve la formulation exacte même quand
    `count`/`unit` restent vides — jamais de fausse précision sur une
    formulation approximative ("environ 90 000 personnes").
    """
    if not text:
        return "", "", ""
    match = _COUNT_RE.search(text)
    if not match:
        return "", "", ""
    raw = match.group(0).strip()
    unit_word = strip_accents(match.group("unit") or "").lower().rstrip(".,;:")
    canonical_unit = _UNIT_MAP.get(unit_word, "")
    if not canonical_unit:
        return "", "", raw
    number = _to_number(match.group("number"), match.group("scale") or "")
    if number is None:
        return "", "", raw
    return str(number), canonical_unit, raw


def _clean_span(raw: str) -> str:
    """Nettoie un nom capturé par regex (tiers, acteur) : `clean_organisation`
    plus la ponctuation de fin de phrase qu'une capture peut aspirer."""
    return clean_organisation(raw).rstrip(" .,;:")


def _normalise_url(value: str) -> str:
    value = (value or "").strip()
    if value and not value.startswith(("http://", "https://")) and "." in value:
        return f"https://{value}"
    return value


# --------------------------------------------------------------------------
# Gabarit commun
# --------------------------------------------------------------------------


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


# --------------------------------------------------------------------------
# BONJOURLAFUITE
# --------------------------------------------------------------------------


def _from_bonjourlafuite(item: Item, entry: RawEntry, spec: SourceSpec) -> dict | None:
    fact = _blank_fact(item, spec)
    evidence: dict = {}
    meta = entry.source_metadata or {}

    claim_status_raw = meta.get("claim_status_raw", "")
    if claim_status_raw:
        fact["Claim_Status_Raw"] = claim_status_raw
        evidence["Claim_Status_Raw"] = claim_status_raw
    # Claim_Status canonique jamais déduit du marqueur : la légende de
    # couleur du site n'est pas vérifiée (ambiguïté -> vide, cf. §13).

    third_party_raw = meta.get("third_party_raw", "")
    if third_party_raw:
        third_party = _clean_span(third_party_raw)
        if third_party:
            fact["Third_Party"] = third_party
            evidence["Third_Party"] = third_party_raw

    data_types_raw = meta.get("data_types_raw", "")
    if data_types_raw:
        data_types = _split_list(data_types_raw)
        if data_types:
            fact["Data_Types_JSON"] = _dumps_json(data_types)
            evidence["Data_Types_JSON"] = data_types_raw

    count, unit, raw_count = _parse_count_phrase(data_types_raw or entry.summary)
    if raw_count:
        fact["Affected_Count_Raw"] = raw_count
        evidence["Affected_Count_Raw"] = raw_count
    if count:
        fact["Affected_Count"] = count
        fact["Affected_Unit"] = unit

    source_urls = meta.get("source_urls") or []
    if source_urls:
        fact["Evidence_URLs_JSON"] = _dumps_json(source_urls)

    return _finalize(fact, entry, evidence)


# --------------------------------------------------------------------------
# FRENCHBREACHES
# --------------------------------------------------------------------------

_CLAIM_STATUS_MAP = (
    # Ordre significatif : la négation doit être testée avant la forme
    # positive, sinon "non confirmée" matcherait aussi "confirmée".
    (re.compile(r"\bnon\s+confirm[ée]e?\b", re.I), "unconfirmed"),
    (re.compile(r"\bd[ée]menti[e]?\b", re.I), "denied"),
    (re.compile(r"\bconfirm[ée]e?\b", re.I), "confirmed"),
    (re.compile(r"\brevendiqu[ée]e?\b", re.I), "claimed"),
)

_ACTOR_RE = re.compile(
    r"revendiqu[ée]e?\s+par\s+(?:le\s+groupe\s+)?([A-Z][\w.&'’-]{1,40})", re.I,
)
_GROUP_RE = re.compile(r"\bgroupe\s+([A-Z][\w.&'’-]{1,40})", re.I)
_THIRD_PARTY_RE = re.compile(
    r"\bvia\s+(?:la\s+plateforme\s+|le\s+prestataire\s+|l['’]h[ée]bergeur\s+)?"
    r"([A-Z][\w.&'’-]{1,40})",
    re.I,
)


def _claim_status(text: str) -> tuple[str, str]:
    for pattern, canonical in _CLAIM_STATUS_MAP:
        match = pattern.search(text or "")
        if match:
            return canonical, match.group(0)
    return "", ""


def _from_frenchbreaches(item: Item, entry: RawEntry, spec: SourceSpec) -> dict | None:
    fact = _blank_fact(item, spec)
    evidence: dict = {}
    text = f"{entry.title} {entry.summary}"

    status_canonical, status_raw = _claim_status(text)
    if status_raw:
        fact["Claim_Status"] = status_canonical
        fact["Claim_Status_Raw"] = status_raw

    count, unit, raw_count = _parse_count_phrase(text)
    if raw_count:
        fact["Affected_Count_Raw"] = raw_count
        evidence["Affected_Count_Raw"] = raw_count
    if count:
        fact["Affected_Count"] = count
        fact["Affected_Unit"] = unit

    volume = _extract_volume(text)
    if volume:
        fact["Data_Volume_Raw"] = volume

    file_count = _extract_file_count(text)
    if file_count:
        fact["File_Count"] = file_count

    actor_match = _ACTOR_RE.search(text) or _GROUP_RE.search(text)
    if actor_match:
        actor = _clean_span(actor_match.group(1))
        if actor:
            fact["Threat_Actor"] = actor
            evidence["Threat_Actor"] = actor_match.group(0)

    third_party_match = _THIRD_PARTY_RE.search(text)
    if third_party_match:
        third_party = _clean_span(third_party_match.group(1))
        if third_party:
            fact["Third_Party"] = third_party
            evidence["Third_Party"] = third_party_match.group(0)

    cves = _extract_cves(text)
    if cves:
        fact["Vulnerabilities_JSON"] = _dumps_json(cves)
        evidence["Vulnerabilities_JSON"] = ", ".join(cves)

    cvss = _extract_cvss(text)
    if cvss:
        fact["CVSS_Raw"] = cvss

    activity = _activity_description(text)
    if activity:
        fact["Activity_Description"] = activity

    return _finalize(fact, entry, evidence)


# --------------------------------------------------------------------------
# CYBERATTAQUE_ORG — relation explicite exigée pour Third_Party/Threat_Actor
# --------------------------------------------------------------------------

_CO_THIRD_PARTY_RE = tuple(re.compile(pattern, re.I) for pattern in (
    r"\b(?:le\s+)?prestataire\s+([A-Z][\w.&'’ -]{1,40}?)\s+(?:a\s+[ée]t[ée]\s+)?compromis",
    r"\bh[ée]berg[ée]e?\s+(?:par|chez)\s+([A-Z][\w.&'’ -]{1,40}?)(?:,|\.|;| qui| également|$)",
    r"\bla\s+plateforme\s+tierce\s+([A-Z][\w.&'’ -]{1,40}?)\s+(?:est\s+)?[àa]\s+l['’]origine",
    r"\bfournisseur\s+([A-Z][\w.&'’ -]{1,40}?)\s+explicitement\s+impliqu[ée]",
))
_CO_THREAT_ACTOR_RE = tuple(re.compile(pattern, re.I) for pattern in (
    r"\b(?:le\s+)?groupe\s+([A-Z][\w.&'’ -]{1,40}?)\s+a\s+revendiqu[ée]",
    r"revendiqu[ée]e?\s+par\s+(?:le\s+groupe\s+)?([A-Z][\w.&'’ -]{1,40})",
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

    for pattern in _CO_THIRD_PARTY_RE:
        match = pattern.search(text)
        if match:
            third_party = _clean_span(match.group(1))
            if third_party:
                fact["Third_Party"] = third_party
                evidence["Third_Party"] = match.group(0).strip()
                break

    for pattern in _CO_THREAT_ACTOR_RE:
        match = pattern.search(text)
        if match:
            actor = _clean_span(match.group(1))
            if actor:
                fact["Threat_Actor"] = actor
                evidence["Threat_Actor"] = match.group(0).strip()
                break

    count, unit, raw_count = _parse_count_phrase(text)
    if raw_count:
        fact["Affected_Count_Raw"] = raw_count
        evidence["Affected_Count_Raw"] = raw_count
    if count:
        fact["Affected_Count"] = count
        fact["Affected_Unit"] = unit

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

    return _finalize(fact, entry, evidence)


# --------------------------------------------------------------------------
# RANSOMWARE_LIVE
# --------------------------------------------------------------------------


def _from_ransomware_live(item: Item, entry: RawEntry, spec: SourceSpec) -> dict | None:
    fact = _blank_fact(item, spec)
    evidence: dict = {}
    meta = entry.source_metadata or {}

    group = meta.get("group", "")
    if group:
        fact["Threat_Actor"] = group
        evidence["Threat_Actor"] = group

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
    if website and website != entry.url:
        fact["Victim_Website"] = website

    urls: list[str] = []
    for candidate in (website, _normalise_url(meta.get("claim_url", ""))):
        if candidate and candidate not in urls:
            urls.append(candidate)
    if urls:
        fact["Evidence_URLs_JSON"] = _dumps_json(urls)

    return _finalize(fact, entry, evidence)


# --------------------------------------------------------------------------
# VEILLE_LLM — déjà structuré, aucune interprétation supplémentaire
# --------------------------------------------------------------------------


def _from_veillellm(item: Item, entry: RawEntry, spec: SourceSpec) -> dict | None:
    fact = _blank_fact(item, spec)
    meta = entry.source_metadata or {}
    if not meta:
        return None

    fine_location = meta.get("localisation", "")
    if fine_location:
        fact["Fine_Location"] = fine_location

    actor = meta.get("acteur", "")
    if actor:
        fact["Threat_Actor"] = actor

    statut = meta.get("statut", "")
    if statut:
        fact["Claim_Status_Raw"] = statut

    score = meta.get("score_cyberattaque")
    if score is not None and str(score) != "":
        fact["Cyberattack_Score"] = str(score)

    impact = meta.get("impact_connu", "")
    if impact:
        fact["Impact"] = impact

    synthese = meta.get("synthese", "")
    if synthese:
        fact["Summary"] = synthese

    evolution = meta.get("evolution", "")
    if evolution:
        fact["Evolution"] = evolution

    sector_raw = meta.get("secteur", "")
    if sector_raw:
        fact["Source_Sector_Raw"] = sector_raw

    sources_list = meta.get("sources") or []
    if sources_list:
        fact["Evidence_URLs_JSON"] = _dumps_json(sources_list)

    return _finalize(fact, entry, {})


# --------------------------------------------------------------------------
# API publique
# --------------------------------------------------------------------------

_EXTRACTORS = {
    "BONJOURLAFUITE": _from_bonjourlafuite,
    "FRENCHBREACHES": _from_frenchbreaches,
    "CYBERATTAQUE_ORG": _from_cyberattaque_org,
    "RANSOMWARE_LIVE": _from_ransomware_live,
    "VEILLE_LLM": _from_veillellm,
}


def extract_source_fact(item: Item, entry: RawEntry, spec: SourceSpec) -> dict | None:
    """Fait source pour un item validé, ou `None` si rien d'extractible.

    Fonctionne uniquement à partir de `item`/`entry`/`spec` : aucun accès
    réseau, aucun appel OpenAI. Une source non listée dans les 5 extracteurs
    actifs ne produit aucune ligne.
    """
    extractor = _EXTRACTORS.get(spec.source_id)
    if extractor is None:
        return None
    return extractor(item, entry, spec)


def merge_source_facts(existing: list[dict], incoming: list[dict]) -> list[dict]:
    """Fusion par `Item_ID` : `incoming` écrase `existing` sur collision,
    tri final déterministe. Même sémantique que `dedup.merge_items`, sans
    les champs propres aux items (§13 — MAJ idempotente)."""
    by_id: dict[str, dict] = {}
    for row in existing:
        item_id = row.get("Item_ID")
        if item_id:
            by_id[item_id] = row
    for row in incoming:
        item_id = row.get("Item_ID")
        if not item_id:
            continue
        by_id[item_id] = row
    return [by_id[key] for key in sorted(by_id)]
