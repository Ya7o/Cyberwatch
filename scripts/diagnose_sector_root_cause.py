#!/usr/bin/env python3
"""Diagnostique de bout en bout la disparition d'une preuve Sector officielle.

Ce script est volontairement read-only. Il observe, sans modifier les données :
source facts -> hints -> découverte de site -> extraction -> identité -> règles
Sector -> attribution au sujet -> resolver officiel -> cache courant -> registre.

Il est générique : une organisation est fournie par CLI. Le workflow de clôture
l'utilise actuellement pour le dernier mismatch Golden connu afin de produire
une preuve exploitable avant tout nouveau changement de règle.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from cyberwatch import (
    company_evidence,
    company_subject_evidence,
    enrichment,
    official_site_discovery,
    sector_registry,
    sector_registry_safety,
    store,
)
from cyberwatch.normalize import organisation_key

KEYWORDS = (
    "construction", "concession", "travaux publics", "génie civil", "genie civil",
    "route", "infrastructure", "transport", "logistique",
)


def _clean(value: str, limit: int = 500) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def _keyword_snippets(text: str) -> list[str]:
    clean = re.sub(r"\s+", " ", text or " ")
    lowered = clean.lower()
    out: list[str] = []
    for keyword in KEYWORDS:
        start = 0
        while True:
            idx = lowered.find(keyword, start)
            if idx < 0:
                break
            snippet = clean[max(0, idx - 140): min(len(clean), idx + 260)]
            snippet = _clean(snippet, 420)
            if snippet and snippet not in out:
                out.append(snippet)
            start = idx + len(keyword)
            if len(out) >= 12:
                return out
    return out


def _source_context(key: str) -> tuple[list[dict], list[str]]:
    items = store.load_items()
    item_by_id = {item.Item_ID: item for item in items if item.Item_ID}
    facts: list[dict] = []
    hints: list[str] = []
    for row in store.read_csv(store.SOURCE_FACTS_CSV):
        item = item_by_id.get((row.get("Item_ID") or "").strip())
        if item is None or item.Organisation_Key != key:
            continue
        observed = {
            "item_id": item.Item_ID,
            "source_id": row.get("Source_ID", ""),
            "source_sector_raw": row.get("Source_Sector_Raw", ""),
            "victim_website": row.get("Victim_Website", ""),
            "item_url": item.URL,
        }
        facts.append(observed)
        website = str(row.get("Victim_Website") or "").strip()
        if website and not website.startswith(("http://", "https://")) and "." in website:
            website = "https://" + website
        if website.startswith(("http://", "https://")) and website not in hints:
            hints.append(website)
    cache = {row.get("Organisation_Key", ""): row for row in store.load_org_enrichment_cache()}
    cached_url = str((cache.get(key) or {}).get("Evidence_URL") or "").strip()
    if cached_url and cached_url not in hints:
        hints.append(cached_url)
    return facts, hints


def _inspect_page(organisation: str, url: str) -> dict:
    result = {
        "candidate_url": url,
        "candidate_domain_match": official_site_discovery.domain_matches_organisation(organisation, url),
        "fetch_ok": False,
        "final_url": "",
        "final_domain_match": False,
        "identity_match": False,
        "priority_len": 0,
        "body_len": 0,
        "about_links": [],
        "keyword_snippets": [],
        "sentence_matches": [],
        "resolver_candidate": None,
    }
    if not result["candidate_domain_match"]:
        return result
    try:
        priority, body, about_links, final_url = company_evidence._page(url)
    except Exception as exc:  # diagnostic: conserver la cause exacte
        result["fetch_error"] = f"{type(exc).__name__}: {exc}"
        return result
    result["fetch_ok"] = bool(priority or body)
    result["priority_len"] = len(priority or "")
    result["body_len"] = len(body or "")
    result["about_links"] = list(about_links or [])[:12]
    evidence_url = final_url or url
    result["final_url"] = evidence_url
    result["final_domain_match"] = official_site_discovery.domain_matches_organisation(organisation, evidence_url)
    if not result["fetch_ok"] or not result["final_domain_match"]:
        return result
    result["identity_match"] = company_evidence._identity_matches(
        organisation, evidence_url, priority, body
    )
    combined = company_evidence._clean(" ".join((priority or "", (body or "")[:16000])))
    result["keyword_snippets"] = _keyword_snippets(combined)
    for sentence in company_subject_evidence._sentences(combined):
        matches = company_subject_evidence._activity_matches(sentence)
        if not matches:
            continue
        matches.sort(key=lambda row: (-row[0], row[1], row[2].start()))
        match_rows = []
        for weight, sector, match in matches:
            match_rows.append({
                "weight": weight,
                "sector": sector,
                "matched_text": match.group(0),
                "subject": company_subject_evidence._org_is_subject(
                    organisation, sentence, match.start()
                ),
            })
        result["sentence_matches"].append({
            "sentence": _clean(sentence, 700),
            "matches": match_rows,
        })
        if len(result["sentence_matches"]) >= 20:
            break
    scored = company_subject_evidence.classify_subject_attributed_activity_scored(
        organisation, combined
    )
    if scored is not None:
        result["resolver_candidate"] = {
            "sector": scored[0], "sentence": _clean(scored[1], 500), "score": scored[2]
        }
    return result


def _classify_root_cause(pages: list[dict], resolved, registry_row: dict | None) -> str:
    if not pages:
        return "DISCOVERY_NO_CANDIDATE"
    accepted = [p for p in pages if p.get("candidate_domain_match")]
    if not accepted:
        return "DISCOVERY_DOMAIN_REJECTED"
    fetched = [p for p in accepted if p.get("fetch_ok")]
    if not fetched:
        return "EXTRACTION_NO_CONTENT"
    identity = [p for p in fetched if p.get("identity_match")]
    if not identity:
        return "IDENTITY_REJECTED"
    if resolved is None:
        if any(p.get("sentence_matches") for p in identity):
            return "ATTRIBUTION_OR_SCORING_REJECTED"
        return "ACTIVITY_NOT_DETECTED"
    if registry_row:
        evidence_types = str(registry_row.get("Evidence_Types") or "")
        if "official_subject_activity" not in evidence_types:
            return "OFFICIAL_FOUND_BUT_NOT_IN_REGISTRY"
        if registry_row.get("Sector") != resolved.sector:
            return "REGISTRY_OVERRIDES_OFFICIAL"
    return "OFFICIAL_RESOLVES_CORRECTLY_CURRENTLY"


def diagnose(key: str, organisation: str) -> dict:
    facts, hints = _source_context(key)
    try:
        candidates = official_site_discovery.discover_official_sites(organisation, tuple(hints))
        discovery_error = ""
    except Exception as exc:
        candidates = []
        discovery_error = f"{type(exc).__name__}: {exc}"

    pages = [_inspect_page(organisation, url) for url in candidates]
    try:
        resolved = company_subject_evidence.resolve_official_site_subject_attributed(
            organisation, candidates
        )
        resolver_error = ""
    except Exception as exc:
        resolved = None
        resolver_error = f"{type(exc).__name__}: {exc}"

    cache_rows = store.load_org_enrichment_cache()
    cache = next((row for row in cache_rows if row.get("Organisation_Key") == key), None)

    items = store.load_items()
    previous_provenance = store.load_qualification_provenance()
    registry = sector_registry.build_registry(
        items,
        enrichment.load_reference(),
        source_fact_rows=store.read_csv(store.SOURCE_FACTS_CSV),
        org_cache_rows=cache_rows,
        previous_provenance=previous_provenance,
    )
    sector_registry_safety.enforce_candidate_conflicts(registry)
    registry_row = next((row for row in registry if row.get("Organisation_Key") == key), None)

    result = {
        "organisation_key": key,
        "organisation": organisation,
        "source_facts": facts,
        "hints": hints,
        "discovery_error": discovery_error,
        "candidates": candidates,
        "pages": pages,
        "resolver_error": resolver_error,
        "resolved_official": None if resolved is None else {
            "sector": resolved.sector,
            "url": resolved.evidence_url,
            "text": _clean(resolved.evidence_text, 700),
            "source": resolved.evidence_source,
            "type": resolved.evidence_type,
        },
        "cache_current": cache,
        "registry_current": registry_row,
    }
    result["root_cause_stage"] = _classify_root_cause(pages, resolved, registry_row)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", required=True)
    parser.add_argument("--organisation", required=True)
    parser.add_argument("--json", default="")
    args = parser.parse_args()
    key = organisation_key(args.key)
    report = diagnose(key, args.organisation)
    print("SECTOR_ROOT_CAUSE_DIAGNOSTIC")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"SECTOR_ROOT_CAUSE_STAGE={report['root_cause_stage']}")
    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"SECTOR_ROOT_CAUSE_JSON={path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
