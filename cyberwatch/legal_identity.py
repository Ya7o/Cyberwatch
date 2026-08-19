"""Rattachement prudent d'un domaine officiel à une identité légale française.

Cette couche n'essaie pas de deviner une entreprise par son nom. Elle part d'un
site officiel déjà validé par les gardes Cyberwatch, extrait un SIREN/SIRET
explicitement étiqueté sur ce domaine, puis vérifie ce SIREN dans le registre
public. Le registre apporte alors une preuve d'activité complémentaire (NAF)
sans risque de sélectionner arbitrairement un homonyme.

Le faisceau v2 ajoute deux signaux indépendants mais conservateurs :
- JSON-LD Organization/LocalBusiness du domaine officiel (nom légal, adresse) ;
- concordance avec le siège ou un établissement renvoyé par le registre.
Aucun de ces signaux ne permet de sélectionner une société sans SIREN exact.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from html.parser import HTMLParser

import requests

from . import company_evidence, official_site_discovery, org_enrichment
from .normalize import searchable

_REGISTRY_URL = org_enrichment.ORG_ENRICHMENT_URL
_TIMEOUT = 8

_SIREN_RE = re.compile(
    r"\b(?:siren|r\.?\s*c\.?\s*s\.?[^\d]{0,40})\s*[:n°º-]*\s*"
    r"([0-9][0-9 .-]{7,14}[0-9])\b",
    re.I,
)
_SIRET_RE = re.compile(
    r"\bsiret\s*[:n°º-]*\s*([0-9][0-9 .-]{12,20}[0-9])\b",
    re.I,
)


@dataclass(frozen=True)
class StructuredIdentity:
    legal_name: str = ""
    name: str = ""
    street: str = ""
    postal_code: str = ""
    city: str = ""
    telephone: str = ""
    description: str = ""


@dataclass(frozen=True)
class LegalIdentityEvidence:
    siren: str
    siret: str
    evidence_url: str
    evidence_text: str
    structured: StructuredIdentity = StructuredIdentity()


class _JsonLdParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._capture = False
        self._parts: list[str] = []
        self.blocks: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() != "script":
            return
        values = {str(k).lower(): str(v or "") for k, v in attrs}
        if values.get("type", "").lower().split(";", 1)[0].strip() == "application/ld+json":
            self._capture = True
            self._parts = []

    def handle_data(self, data: str) -> None:
        if self._capture:
            self._parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._capture:
            value = "".join(self._parts).strip()
            if value:
                self.blocks.append(value)
            self._capture = False
            self._parts = []


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value or "")


def _norm(value: str) -> str:
    return searchable(str(value or ""))


def extract_legal_ids(text: str) -> tuple[str, str]:
    """Extrait uniquement des identifiants explicitement étiquetés."""
    value = company_evidence._clean(text)
    siret = ""
    siren = ""

    match = _SIRET_RE.search(value)
    if match:
        candidate = _digits(match.group(1))
        if len(candidate) == 14:
            siret = candidate
            siren = candidate[:9]

    if not siren:
        match = _SIREN_RE.search(value)
        if match:
            candidate = _digits(match.group(1))
            if len(candidate) == 9:
                siren = candidate

    return siren, siret


def _jsonld_nodes(payload) -> list[dict]:
    if isinstance(payload, dict):
        nodes: list[dict] = []
        graph = payload.get("@graph")
        if isinstance(graph, list):
            nodes.extend(row for row in graph if isinstance(row, dict))
        nodes.append(payload)
        return nodes
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    return []


def extract_structured_identity(html_text: str) -> StructuredIdentity:
    """Extrait les champs d'identité depuis JSON-LD Organization/LocalBusiness."""
    parser = _JsonLdParser()
    try:
        parser.feed(html_text or "")
    except Exception:
        return StructuredIdentity()

    candidates: list[dict] = []
    for block in parser.blocks:
        try:
            payload = json.loads(block)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        for node in _jsonld_nodes(payload):
            raw_type = node.get("@type")
            types = raw_type if isinstance(raw_type, list) else [raw_type]
            normalized = {_norm(value) for value in types if value}
            if normalized.intersection({"organization", "corporation", "localbusiness", "store", "professionalservice"}):
                candidates.append(node)

    if not candidates:
        return StructuredIdentity()

    node = candidates[0]
    address = node.get("address") if isinstance(node.get("address"), dict) else {}
    return StructuredIdentity(
        legal_name=str(node.get("legalName") or "").strip(),
        name=str(node.get("name") or "").strip(),
        street=str(address.get("streetAddress") or "").strip(),
        postal_code=str(address.get("postalCode") or "").strip(),
        city=str(address.get("addressLocality") or "").strip(),
        telephone=str(node.get("telephone") or "").strip(),
        description=company_evidence._clean(str(node.get("description") or ""))[:500],
    )


def _fetch_structured_identity(url: str) -> StructuredIdentity:
    response = company_evidence._http_get(url, timeout=_TIMEOUT)
    if response is None:
        return StructuredIdentity()
    return extract_structured_identity(response.text)


def _snippet(text: str, siren: str, siret: str) -> str:
    compact = company_evidence._clean(text)
    needle = siret or siren
    if not needle:
        return ""
    digits_only = re.sub(r"\D", "", compact)
    if needle not in digits_only:
        return compact[:500]
    for marker in ("SIRET", "SIREN", "RCS", "siret", "siren", "rcs"):
        pos = compact.find(marker)
        if pos >= 0:
            return compact[max(0, pos - 100): pos + 400]
    return compact[:500]


def discover_from_official_site(organisation: str) -> LegalIdentityEvidence | None:
    """Cherche un SIREN/SIRET seulement sur un domaine officiel validé."""
    try:
        candidates = official_site_discovery.discover_official_sites(organisation)
    except Exception:
        return None

    for candidate in candidates:
        if not official_site_discovery.domain_matches_organisation(organisation, candidate):
            continue
        priority, body, about_links, final_url = company_evidence._page(candidate)
        evidence_url = final_url or candidate
        if not priority and not body:
            continue
        if not official_site_discovery.domain_matches_organisation(organisation, evidence_url):
            continue
        if not company_evidence._identity_matches(organisation, evidence_url, priority, body):
            continue

        structured = _fetch_structured_identity(evidence_url)
        text = company_evidence._clean(" ".join((priority, body)))
        siren, siret = extract_legal_ids(text)
        if siren:
            return LegalIdentityEvidence(
                siren, siret, evidence_url, _snippet(text, siren, siret), structured
            )

        for link in about_links[:4]:
            if not official_site_discovery.domain_matches_organisation(organisation, link):
                continue
            p_priority, p_body, _links, p_final = company_evidence._page(link)
            page_url = p_final or link
            if not p_priority and not p_body:
                continue
            if not official_site_discovery.domain_matches_organisation(organisation, page_url):
                continue
            text = company_evidence._clean(" ".join((p_priority, p_body)))
            siren, siret = extract_legal_ids(text)
            if siren:
                if structured == StructuredIdentity():
                    structured = _fetch_structured_identity(page_url)
                return LegalIdentityEvidence(
                    siren, siret, page_url, _snippet(text, siren, siret), structured
                )
    return None


def fetch_registry_candidate(siren: str) -> dict | None:
    """Retourne uniquement le candidat du registre portant exactement le SIREN."""
    if not re.fullmatch(r"\d{9}", siren or ""):
        return None
    try:
        response = requests.get(
            _REGISTRY_URL,
            params={"q": siren, "per_page": 5},
            timeout=_TIMEOUT,
        )
        if response.status_code != 200:
            return None
        payload = response.json()
    except (requests.RequestException, ValueError):
        return None
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        return None
    exact = [
        row for row in results
        if isinstance(row, dict) and str(row.get("siren") or "").strip() == siren
    ]
    return exact[0] if len(exact) == 1 else None


def _candidate_establishments(candidate: dict) -> list[dict]:
    rows: list[dict] = []
    siege = candidate.get("siege")
    if isinstance(siege, dict):
        rows.append(siege)
    for field_name in ("matching_etablissements", "etablissements"):
        values = candidate.get(field_name)
        if isinstance(values, list):
            rows.extend(row for row in values if isinstance(row, dict))
    return rows


def _establishment_score(row: dict, evidence: LegalIdentityEvidence) -> int:
    score = 0
    row_siret = _digits(str(row.get("siret") or ""))
    if evidence.siret and row_siret == evidence.siret:
        score += 10

    structured = evidence.structured
    row_postal = _norm(row.get("code_postal") or row.get("postal_code") or "")
    row_city = _norm(row.get("libelle_commune") or row.get("commune") or row.get("ville") or "")
    row_address = _norm(
        " ".join(
            str(row.get(key) or "")
            for key in ("numero_voie", "type_voie", "libelle_voie", "adresse", "adresse_complete")
        )
    )
    if structured.postal_code and row_postal == _norm(structured.postal_code):
        score += 3
    if structured.city and row_city and row_city == _norm(structured.city):
        score += 3
    street = _norm(structured.street)
    if street and row_address and (street in row_address or row_address in street):
        score += 4
    return score


def best_establishment(candidate: dict, evidence: LegalIdentityEvidence) -> tuple[dict, int]:
    rows = _candidate_establishments(candidate)
    if not rows:
        return {}, 0
    scored = sorted(
        ((_establishment_score(row, evidence), index, row) for index, row in enumerate(rows)),
        key=lambda value: (-value[0], value[1]),
    )
    score, _index, row = scored[0]
    return row, score


def _department(row: dict) -> str:
    return str(row.get("departement") or "").strip()


def cache_row(
    organisation_key: str,
    query_name: str,
    fetched_at: str,
    evidence: LegalIdentityEvidence,
    candidate: dict,
) -> dict:
    """Construit une ligne compatible avec le cache organisation existant."""
    establishment, establishment_score = best_establishment(candidate, evidence)
    section = str(
        establishment.get("section_activite_principale")
        or candidate.get("section_activite_principale")
        or ""
    )
    activity_label = (
        ""
        if section in org_enrichment.AMBIGUOUS_NAF_SECTIONS
        else org_enrichment.NAF_SECTION_LABELS.get(section, "")
    )
    activity_code = str(
        establishment.get("activite_principale")
        or candidate.get("activite_principale")
        or ""
    )
    department = _department(establishment)
    if not department:
        siege = candidate.get("siege")
        department = _department(siege) if isinstance(siege, dict) else ""
    matched_name = str(candidate.get("nom_raison_sociale") or candidate.get("nom_complet") or "")

    if evidence.siret and establishment_score >= 10:
        validated_via = "legal_identity_siret"
    elif establishment_score >= 6:
        validated_via = "legal_identity_address"
    else:
        validated_via = "legal_identity"

    return {
        "Organisation_Key": organisation_key,
        "Query_Name": query_name,
        # Query_Name conserve la marque vue dans les sources ; Matched_Name
        # conserve l'entité légale. Ce couple constitue l'alias canonique sans
        # introduire un second registre parallèle.
        "Matched_Name": matched_name,
        "Company_ID": evidence.siren,
        "Activity_Code": activity_code,
        "Activity_Label": activity_label,
        "Headquarters_Department": department,
        "Evidence_Source": "official_site+siren_registry",
        "Evidence_URL": evidence.evidence_url,
        "Match_Status": org_enrichment.MATCHED,
        "Fetched_At": fetched_at,
        "Validated_Sector": "",
        "Validated_Via": validated_via,
        "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
    }


def resolve(
    organisation_key: str,
    query_name: str,
    fetched_at: str,
) -> dict | None:
    evidence = discover_from_official_site(query_name)
    if evidence is None:
        return None
    candidate = fetch_registry_candidate(evidence.siren)
    if candidate is None:
        return None
    return cache_row(organisation_key, query_name, fetched_at, evidence, candidate)
