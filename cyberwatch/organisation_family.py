"""Référentiel déterministe de familles organisationnelles françaises.

Le module ne fait aucun accès réseau. Il convertit un nom suffisamment
auto-descriptif (nom complet, alias exact ou sigle contrôlé) en une famille et
un secteur Cyberwatch avec provenance. Il ne remplace ni l'identité
organisationnelle ni le registre SIRENE/NAF : il constitue un canal de preuve
institutionnelle supplémentaire.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from . import config
from .normalize import searchable

REFERENCE_CSV = Path(__file__).resolve().parents[1] / "reference" / "organisation_families.csv"

_COMMERCIAL_SUFFIXES = frozenset({
    "consulting", "technologies", "technology", "solutions", "digital",
    "systems", "systemes", "software", "services", "group", "groupe",
    "industrie", "industries", "holding", "partners", "conseil", "safety",
})
_TERRITORIAL_PREFIXES = (
    "de ", "du ", "des ", "d ", "la ", "le ", "les ", "en ", "au ", "aux ",
)


def _parts(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in str(value or "").split("|") if part.strip())


@dataclass(frozen=True)
class OrganisationFamilyRule:
    family_id: str
    canonical_type: str
    sector: str
    acronyms: tuple[str, ...]
    acronym_mode: str
    full_name_prefixes: tuple[str, ...]
    aliases: tuple[str, ...]
    confidence: str
    authority: str
    source: str
    source_url: str


@dataclass(frozen=True)
class OrganisationFamilyMatch:
    family_id: str
    canonical_type: str
    sector: str
    confidence: str
    authority: str
    source: str
    source_url: str
    matched_by: str
    matched_value: str

    @property
    def evidence_text(self) -> str:
        return f"famille={self.family_id}; type={self.canonical_type}; match={self.matched_by}:{self.matched_value}"


@lru_cache(maxsize=4)
def load_rules(path: str = "") -> tuple[OrganisationFamilyRule, ...]:
    target = Path(path) if path else REFERENCE_CSV
    if not target.exists():
        return ()
    rules: list[OrganisationFamilyRule] = []
    with target.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            sector = str(row.get("Sector") or "").strip()
            if sector not in config.SECTORS or sector == config.SECTOR_UNKNOWN:
                continue
            rules.append(OrganisationFamilyRule(
                family_id=str(row.get("Family_ID") or "").strip(),
                canonical_type=str(row.get("Canonical_Type") or "").strip(),
                sector=sector,
                acronyms=tuple(searchable(v) for v in _parts(row.get("Acronyms", ""))),
                acronym_mode=str(row.get("Acronym_Mode") or "exact").strip().lower(),
                full_name_prefixes=tuple(searchable(v) for v in _parts(row.get("Full_Name_Prefixes", ""))),
                aliases=tuple(searchable(v) for v in _parts(row.get("Aliases", ""))),
                confidence=str(row.get("Confidence") or "HIGH").strip().upper(),
                authority=str(row.get("Authority") or "REFERENCE").strip().upper(),
                source=str(row.get("Source") or "organisation_families.csv").strip(),
                source_url=str(row.get("Source_URL") or "").strip(),
            ))
    return tuple(rules)


def _acronym_matches(blob: str, acronym: str, mode: str) -> bool:
    if not acronym:
        return False
    if blob == acronym:
        return True
    prefix = acronym + " "
    if not blob.startswith(prefix):
        return False
    rest = blob[len(prefix):].strip()
    if not rest:
        return True
    first = rest.split(" ", 1)[0]
    if first in _COMMERCIAL_SUFFIXES:
        return False
    if mode == "union":
        return True
    if mode == "territorial":
        return first[:1].isdigit() or rest.startswith(_TERRITORIAL_PREFIXES)
    return False


def match_organisation_family(name: str, *, path: str = "") -> OrganisationFamilyMatch | None:
    blob = searchable(name)
    if not blob:
        return None
    rules = load_rules(path)

    # 1. Alias exact : aucun risque de sous-chaîne.
    for rule in rules:
        for alias in rule.aliases:
            if blob == alias:
                return OrganisationFamilyMatch(
                    rule.family_id, rule.canonical_type, rule.sector, rule.confidence,
                    rule.authority, rule.source, rule.source_url, "alias", alias,
                )

    # 2. Nom institutionnel complet, ancré au début. Les plus longs gagnent.
    prefix_candidates: list[tuple[int, OrganisationFamilyRule, str]] = []
    for rule in rules:
        for prefix in rule.full_name_prefixes:
            if blob == prefix or blob.startswith(prefix + " "):
                prefix_candidates.append((len(prefix), rule, prefix))
    if prefix_candidates:
        _length, rule, prefix = max(prefix_candidates, key=lambda value: (value[0], value[1].family_id))
        return OrganisationFamilyMatch(
            rule.family_id, rule.canonical_type, rule.sector, rule.confidence,
            rule.authority, rule.source, rule.source_url, "full_name", prefix,
        )

    # 3. Sigle. Les modes évitent les collisions commerciales du type
    # « SDIS Consulting » ou « CGT Solutions ».
    for rule in rules:
        for acronym in rule.acronyms:
            if _acronym_matches(blob, acronym, rule.acronym_mode):
                return OrganisationFamilyMatch(
                    rule.family_id, rule.canonical_type, rule.sector, rule.confidence,
                    rule.authority, rule.source, rule.source_url, "acronym", acronym,
                )
    return None


def validate_reference(*, path: str = "") -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for rule in load_rules(path):
        if not rule.family_id:
            errors.append("family_id_missing")
        elif rule.family_id in seen:
            errors.append(f"duplicate_family:{rule.family_id}")
        seen.add(rule.family_id)
        if not rule.full_name_prefixes and not rule.aliases and not rule.acronyms:
            errors.append(f"family_without_matcher:{rule.family_id}")
    return sorted(errors)
