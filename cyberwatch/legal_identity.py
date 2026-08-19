"""Rattachement prudent d'un domaine officiel à une identité légale française.

Cette couche n'essaie pas de deviner une entreprise par son nom. Elle part d'un
site officiel déjà validé par les gardes Cyberwatch, extrait un SIREN/SIRET
explicitement étiqueté sur ce domaine, puis vérifie ce SIREN dans le registre
public. Le registre apporte alors une preuve d'activité complémentaire (NAF)
sans risque de sélectionner arbitrairement un homonyme.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import requests

from . import company_evidence, official_site_discovery, org_enrichment

_REGISTRY_URL = org_enrichment.ORG_ENRICHMENT_URL
_TIMEOUT = 8

# On exige un libellé légal proche du nombre : une suite de 9 chiffres trouvée
# ailleurs dans la page (téléphone, montant, identifiant technique) n'est jamais
# interprétée comme SIREN.
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
class LegalIdentityEvidence:
    siren: str
    siret: str
    evidence_url: str
    evidence_text: str


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value or "")


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


def _snippet(text: str, siren: str, siret: str) -> str:
    compact = company_evidence._clean(text)
    needle = siret or siren
    if not needle:
        return ""
    digits_only = re.sub(r"\D", "", compact)
    # Si l'espacement empêche de retrouver directement le numéro, garder un
    # extrait borné de la page : la preuve reste consultable via Evidence_URL.
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

        for text, url in ((company_evidence._clean(" ".join((priority, body))), evidence_url),):
            siren, siret = extract_legal_ids(text)
            if siren:
                return LegalIdentityEvidence(siren, siret, url, _snippet(text, siren, siret))

        # Les liens "mentions légales" sont déjà collectés par _PageParser dans
        # about_links. Une fois le domaine parent validé, une page du même domaine
        # peut servir à extraire l'identifiant même si elle affiche la raison
        # sociale plutôt que la marque commerciale.
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
                return LegalIdentityEvidence(siren, siret, page_url, _snippet(text, siren, siret))
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


def cache_row(
    organisation_key: str,
    query_name: str,
    fetched_at: str,
    evidence: LegalIdentityEvidence,
    candidate: dict,
) -> dict:
    """Construit une ligne compatible avec le cache organisation existant."""
    section = str(candidate.get("section_activite_principale") or "")
    activity_label = (
        ""
        if section in org_enrichment.AMBIGUOUS_NAF_SECTIONS
        else org_enrichment.NAF_SECTION_LABELS.get(section, "")
    )
    siege = candidate.get("siege")
    department = str(siege.get("departement") or "") if isinstance(siege, dict) else ""
    matched_name = str(candidate.get("nom_raison_sociale") or candidate.get("nom_complet") or "")
    return {
        "Organisation_Key": organisation_key,
        "Query_Name": query_name,
        "Matched_Name": matched_name,
        "Company_ID": evidence.siren,
        "Activity_Code": str(candidate.get("activite_principale") or ""),
        "Activity_Label": activity_label,
        "Headquarters_Department": department,
        "Evidence_Source": "official_site+siren_registry",
        "Evidence_URL": evidence.evidence_url,
        "Match_Status": org_enrichment.MATCHED,
        "Fetched_At": fetched_at,
        "Validated_Sector": "",
        "Validated_Via": "legal_identity",
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
