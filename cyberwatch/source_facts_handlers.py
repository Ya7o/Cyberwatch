"""Extracteurs par source et fusion des faits publiables."""

from __future__ import annotations

import logging
import re

from . import config, source_facts_ai
from .collectors.base import RawEntry, SourceSpec
from .model import SOURCE_FACT_COLUMNS, Item
from .normalize import parse_date
from .source_facts import (
    _ACTOR_PATTERNS,
    _THIRD_PARTY_PATTERNS,
    _ai_activity,
    _ai_count,
    _ai_data_types,
    _ai_file_count,
    _ai_sector_match,
    _ai_text,
    _ai_threat_candidate,
    _ai_volume,
    _apply_semantic_enrichment,
    _blank_fact,
    _claim_status,
    _derive_summary,
    _dumps_json,
    _extract_cves,
    _extract_cvss,
    _extract_file_count,
    _extract_victim_activity,
    _extract_volume,
    _finalize,
    _first_valid_match,
    _from_bonjourlafuite,
    _loads_json,
    _native_frenchbreaches_sector,
    _normalise_url,
    _parse_count_phrase,
    _valid_actor,
    _valid_third_party,
)

logger = logging.getLogger(__name__)


def _apply_semantic_details(
    fact: dict,
    evidence: dict,
    ai_result: dict,
    text: str,
    organisation: str,
    entry: RawEntry,
) -> None:
    metadata = _loads_json(fact.get("Source_Metadata_JSON", "")) or {}
    metadata["editorial_context"] = (entry.content or entry.summary)[:12000]
    fact["Source_Metadata_JSON"] = _dumps_json(metadata)
    volume, volume_evidence = _ai_volume(ai_result)
    volume = volume or _extract_volume(text)
    if volume:
        fact["Data_Volume_Raw"] = volume
        if volume_evidence:
            evidence["Data_Volume_Raw"] = volume_evidence
    file_count, file_evidence = _ai_file_count(ai_result)
    file_count = file_count or _extract_file_count(text)
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
    cves = sorted(
        set(_extract_cves(text))
        | set(_loads_json(fact.get("Vulnerabilities_JSON", "")) or [])
    )
    if cves:
        fact["Vulnerabilities_JSON"] = _dumps_json(cves)
        evidence["Vulnerabilities_JSON"] = ", ".join(cves)
    cvss = _extract_cvss(text)
    if cvss:
        fact["CVSS_Raw"] = cvss
    llm_activity, activity_evidence = _ai_activity(ai_result, organisation)
    activity = llm_activity or _extract_victim_activity(
        organisation, entry.title, entry.summary, entry.content
    )
    from .sector_activity import activity_from_text
    literal_activity, literal_proof = activity_from_text(
        organisation, entry.summary, entry.content
    )
    if not llm_activity and literal_activity:
        activity, activity_evidence = literal_activity, literal_proof
    if activity:
        fact["Activity_Description"] = activity
        if activity_evidence:
            evidence["Activity_Description"] = activity_evidence
    sector_match, sector_evidence = (
        _ai_sector_match(ai_result) if llm_activity else ("", "")
    )
    if sector_match:
        fact["Activity_Sector_Match"] = sector_match
        evidence["Activity_Sector_Match"] = sector_evidence


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

    _apply_semantic_details(fact, evidence, ai_result, text, organisation, entry)
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
    # « X indique » désigne très souvent la victime qui communique sur son
    # propre incident (cas réels Euskal Moneta et L Commerce) et est donc
    # exclu. Les verbes actifs de revendication restent acceptés, puis passent
    # par `_valid_actor` et le résolveur de victime secondaire.
    r"\b([A-Za-z0-9][\w.&'’+-]{1,40})\s+(?:revendique|affirme|d[ée]clare)\b",
))
_CO_INITIAL_ACCESS_PATTERNS = tuple(re.compile(pattern, re.I) for pattern in (
    # Catégorie factuelle, sans inférer le prestataire ni le mode technique.
    r"(\b(?:cyberattaque|compromission|incident)\b.{0,80}\b(?:chez\s+(?:un|une)|d['’]un)\s+(?:prestataire|tiers)\b)",
    r"(\b(?:prestataire|tiers)\b.{0,40}\bcompromis\b)",
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

    # Le LLM, s'il a une preuve, reste prioritaire ; ce repli ne classe que
    # la compromission explicitement attribuée à un tiers dans le texte.
    if not fact.get("Initial_Access"):
        initial_access, initial_evidence = _first_valid_match(
            _CO_INITIAL_ACCESS_PATTERNS, text, lambda value, _organisation: value, organisation
        )
        if initial_access:
            fact["Initial_Access"] = "third_party"
            evidence["Initial_Access"] = initial_evidence

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

    _apply_semantic_details(fact, evidence, ai_result, text, organisation, entry)

    website_match = _WEBSITE_RE.search(text)
    if website_match:
        website = _normalise_url(website_match.group(1))
        if website:
            fact["Victim_Website"] = website
            evidence["Victim_Website"] = website_match.group(0).strip()

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


def _pending_fact_clears(old_meta: dict, new_meta: dict, new: dict,
                         field_columns: dict[str, str]) -> tuple[dict, bool, str, dict]:
    old_hash = str(old_meta.get("_source_facts_content_hash") or "")
    new_hash = str(new_meta.get("_source_facts_content_hash") or "")
    content_changed = bool(old_hash and new_hash and old_hash != new_hash)
    statuses = new_meta.get("_source_facts_semantic_status")
    statuses = statuses if isinstance(statuses, dict) else {}
    pending = old_meta.get("_source_facts_pending_clear")
    pending = dict(pending) if isinstance(pending, dict) else {}
    for column, field in field_columns.items():
        state = str(statuses.get(field) or "").lower()
        if new.get(column, "") not in (None, ""):
            pending.pop(field, None)
        elif content_changed and state in {"miss", "abstained"} and new_hash:
            pending[field] = new_hash
    return pending, content_changed, new_hash, statuses


def _should_clear_fact(column: str, new: dict, new_meta: dict, field_columns: dict,
                       pending: dict, content_changed: bool, new_hash: str,
                       statuses: dict) -> bool:
    field = field_columns.get(column, "")
    if column == "Summary" and new_meta.get("_source_facts_summary_status") in {
        "rejected_quality", "abstained", "technical_failure",
    }:
        return True
    return bool(
        field and statuses.get(field) == "abstained" and new.get(column, "") in (None, "")
        and (content_changed or pending.get(field) == new_hash)
    )


def merge_source_facts(existing: list[dict], incoming: list[dict]) -> list[dict]:
    refreshable = {"Summary", "Initial_Access", "Attack_Flow_JSON", "Impact", "Activity_Description", "Activity_Sector_Match"}
    base = {"Item_ID", "Source_ID", "Extraction_Method", "Extraction_Version", "Source_Metadata_JSON"}

    ai_field_for_column = {
        "Summary": "summary",
        "Initial_Access": "initial_access",
        "Attack_Flow_JSON": "attack_flow",
        "Impact": "impact",
        "Activity_Description": "activity_description",
        "Activity_Sector_Match": "activity_sector_match",
    }

    def merge_row(old: dict, new: dict) -> dict:
        merged = dict(old)
        old_evidence = _loads_json(str(old.get("Evidence_JSON") or ""))
        new_evidence = _loads_json(str(new.get("Evidence_JSON") or ""))
        evidence = dict(old_evidence) if isinstance(old_evidence, dict) else {}
        old_meta = _loads_json(str(old.get("Source_Metadata_JSON") or ""))
        new_meta = _loads_json(str(new.get("Source_Metadata_JSON") or ""))
        old_meta = old_meta if isinstance(old_meta, dict) else {}
        new_meta = new_meta if isinstance(new_meta, dict) else {}
        # Une réhydratation peut ne produire que le hash de contenu. Conserver
        # alors les faits riches déjà extraits plutôt que de les effacer à la
        # faveur du rafraîchissement d'un champ SourceFacts.
        merged_meta = dict(old_meta)
        merged_meta.update(new_meta)
        new = dict(new)
        pending_clear, content_changed, new_hash, refresh_status = _pending_fact_clears(
            old_meta, new_meta, new, ai_field_for_column
        )

        def should_clear(column: str) -> bool:
            return _should_clear_fact(
                column, new, new_meta, ai_field_for_column, pending_clear,
                content_changed, new_hash, refresh_status,
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
                    pending_clear.pop(ai_field_for_column.get(column, ""), None)
            elif column in base:
                if value not in (None, ""):
                    merged[column] = value
            elif value not in (None, ""):
                merged[column] = value
        if pending_clear:
            merged_meta["_source_facts_pending_clear"] = pending_clear
        else:
            merged_meta.pop("_source_facts_pending_clear", None)
        merged["Source_Metadata_JSON"] = _dumps_json(merged_meta)
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
