from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"replacement anchor not found in {path}: {old[:120]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


def append_once(path: str, marker: str, block: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    if marker in text:
        return
    target.write_text(text.rstrip() + "\n\n" + block.strip() + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# 1. Taxonomie : une organisation syndicale ne doit plus être forcée dans B2B.
# ---------------------------------------------------------------------------
replace_once(
    "cyberwatch/config.py",
    'SECTOR_SERVICES = "Services aux entreprises"\nSECTOR_UNKNOWN = "Inconnu"',
    'SECTOR_SERVICES = "Services aux entreprises"\nSECTOR_ASSOCIATION = "Association / Syndicat"\nSECTOR_UNKNOWN = "Inconnu"',
)
replace_once(
    "cyberwatch/config.py",
    "    SECTOR_CONSTRUCTION,\n    SECTOR_SERVICES,\n    SECTOR_UNKNOWN,",
    "    SECTOR_CONSTRUCTION,\n    SECTOR_SERVICES,\n    SECTOR_ASSOCIATION,\n    SECTOR_UNKNOWN,",
)
replace_once(
    "cyberwatch/config.py",
    '    "staffing recruiting": SECTOR_SERVICES,\n',
    '    "staffing recruiting": SECTOR_SERVICES,\n'
    '    "trade union": SECTOR_ASSOCIATION,\n'
    '    "labor union": SECTOR_ASSOCIATION,\n'
    '    "professional association": SECTOR_ASSOCIATION,\n'
    '    "nonprofit organization": SECTOR_ASSOCIATION,\n'
    '    "non profit organization": SECTOR_ASSOCIATION,\n',
)
replace_once(
    "cyberwatch/config.py",
    "    (SECTOR_HEALTH, [\n",
    "    (SECTOR_ASSOCIATION, [\n"
    "        \"organisation syndicale\", \"syndicat professionnel\", \"union syndicale\",\n"
    "        \"confederation syndicale\", \"federation syndicale\", \"trade union\",\n"
    "        \"labor union\", \"organisation a but non lucratif\",\n"
    "    ]),\n"
    "    (SECTOR_HEALTH, [\n",
)

# ---------------------------------------------------------------------------
# 2. Référentiel déterministe de familles d'organisations.
# ---------------------------------------------------------------------------
reference_dir = ROOT / "reference"
reference_dir.mkdir(parents=True, exist_ok=True)
(reference_dir / "organisation_families.csv").write_text("""Family_ID,Canonical_Type,Sector,Acronyms,Acronym_Mode,Full_Name_Prefixes,Aliases,Confidence,Authority,Source,Source_URL
FR_SDIS,Service départemental d'incendie et de secours,Administration / Collectivité,SDIS,territorial,service departemental d incendie et de secours|service d incendie et de secours,,HIGH,STATUTORY_FAMILY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_PREFECTURE,Préfecture et sous-préfecture,Administration / Collectivité,,,prefecture de|sous prefecture de,,HIGH,STATUTORY_FAMILY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_MINISTRY,Ministère,Administration / Collectivité,,,ministere de|ministere des,,HIGH,STATUTORY_FAMILY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_LOCAL_AUTHORITY,Collectivité territoriale,Administration / Collectivité,,,mairie de|ville de|commune de|conseil departemental|conseil regional|departement de|region de,,HIGH,STATUTORY_FAMILY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_INTERCOMMUNALITY,Intercommunalité et établissement territorial,Administration / Collectivité,,,metropole de|communaute de communes|communaute d agglomeration|communaute urbaine|etablissement public territorial|syndicat mixte,,HIGH,STATUTORY_FAMILY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_CCAS_CIAS,Action sociale communale,Administration / Collectivité,CCAS|CIAS,territorial,centre communal d action sociale|centre intercommunal d action sociale,,HIGH,STATUTORY_FAMILY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_CAF,Caisse d'allocations familiales,Administration / Collectivité,CAF,territorial,caisse d allocations familiales,,HIGH,STATUTORY_FAMILY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_CPAM,Caisse primaire d'assurance maladie,Administration / Collectivité,CPAM,territorial,caisse primaire d assurance maladie,,HIGH,STATUTORY_FAMILY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_CGSS,Caisse générale de sécurité sociale,Administration / Collectivité,CGSS,territorial,caisse generale de securite sociale,,HIGH,STATUTORY_FAMILY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_URSSAF,URSSAF,Administration / Collectivité,URSSAF,territorial,union de recouvrement des cotisations de securite sociale et d allocations familiales,,HIGH,STATUTORY_FAMILY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_ARS,Agence régionale de santé,Santé,ARS,territorial,agence regionale de sante,ars auvergne rhone alpes|ars bourgogne franche comte|ars bretagne|ars centre val de loire|ars corse|ars grand est|ars guadeloupe|ars guyane|ars hauts de france|ars ile de france|ars martinique|ars mayotte|ars normandie|ars nouvelle aquitaine|ars occitanie|ars pays de la loire|ars provence alpes cote d azur|ars reunion,HIGH,STATUTORY_FAMILY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_CHU,Centre hospitalier universitaire,Santé,CHU,territorial,centre hospitalier universitaire,,HIGH,STATUTORY_FAMILY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_CHR,Centre hospitalier régional,Santé,CHR,territorial,centre hospitalier regional,,HIGH,STATUTORY_FAMILY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_HOSPITAL,Établissement hospitalier public,Santé,,,centre hospitalier de|hopital de|hospices civils,,HIGH,STATUTORY_FAMILY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_CROUS,Centre régional des œuvres universitaires et scolaires,Éducation / Formation,CROUS,territorial,centre regional des oeuvres universitaires et scolaires,,HIGH,STATUTORY_FAMILY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_RECTORAT,Administration académique,Éducation / Formation,,,rectorat de|academie de,,HIGH,STATUTORY_FAMILY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_UNIVERSITY,Université,Éducation / Formation,,,universite de,,HIGH,STATUTORY_FAMILY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_CNRS,Centre national de la recherche scientifique,Éducation / Formation,CNRS,exact,centre national de la recherche scientifique,cnrs,HIGH,OFFICIAL_ENTITY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_INSERM,Institut national de la santé et de la recherche médicale,Santé,INSERM,exact,institut national de la sante et de la recherche medicale,inserm,HIGH,OFFICIAL_ENTITY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_JUSTICE,Juridiction publique,Administration / Collectivité,,,tribunal judiciaire de|tribunal administratif de|cour d appel de|cour administrative d appel de,,HIGH,STATUTORY_FAMILY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_FRANCE_TRAVAIL,Service public de l'emploi,Administration / Collectivité,,,france travail,pole emploi,HIGH,OFFICIAL_ENTITY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_ANSSI,Agence nationale de la sécurité des systèmes d'information,Administration / Collectivité,ANSSI,exact,agence nationale de la securite des systemes d information,anssi,HIGH,OFFICIAL_ENTITY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_CCI,Chambre de commerce et d'industrie,Commerce / Distribution,CCI,territorial,chambre de commerce et d industrie,,HIGH,STATUTORY_FAMILY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_CMA,Chambre de métiers et de l'artisanat,Commerce / Distribution,CMA,territorial,chambre de metiers et de l artisanat,,HIGH,STATUTORY_FAMILY,Annuaire de l'administration française,https://lannuaire.service-public.fr/
FR_TRADE_UNION,Organisation syndicale,Association / Syndicat,CGT|CFDT|CFTC|FSU|UNSA|CFE CGC,union,confederation generale du travail|confederation francaise democratique du travail|force ouvriere|confederation francaise des travailleurs chretiens|federation syndicale unitaire|union nationale des syndicats autonomes|union syndicale solidaires|syndicat sud,,HIGH,STATUTORY_FAMILY,Référentiel organisationnel Cyberwatch,
FR_PROFESSIONAL_UNION,Organisation syndicale ou professionnelle,Association / Syndicat,,,syndicat professionnel|union syndicale|confederation syndicale|federation syndicale,,HIGH,STATUTORY_FAMILY,Référentiel organisationnel Cyberwatch,
""", encoding="utf-8")

(reference_dir / "README.md").write_text("""# Référentiel organisationnel

`organisation_families.csv` contient les familles dont le nom ou le sigle est suffisamment auto-descriptif pour constituer une preuve déterministe de secteur.

Principes :

- correspondances ancrées sur le nom complet, un alias exact ou un sigle contrôlé ;
- aucun simple mot de marque n'est admis ;
- chaque famille porte une provenance et un niveau d'autorité ;
- les identifiants entreprise/NAF continuent d'être absorbés par le registre entreprise existant ;
- les entités exactes validées manuellement restent prioritaires ;
- une famille institutionnelle certaine évite un appel LLM et produit une preuve auditée.

Le fichier est volontairement versionné dans le dépôt : la collecte quotidienne ne dépend pas de la disponibilité temps réel d'un annuaire externe. Les mises à jour peuvent être construites à partir de l'Annuaire de l'administration française, de SIRENE/recherche-entreprises et des référentiels métiers officiels, puis revues avant publication.
""", encoding="utf-8")

(ROOT / "cyberwatch" / "organisation_family.py").write_text(r'''"""Référentiel déterministe de familles organisationnelles françaises.

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
''', encoding="utf-8")

# ---------------------------------------------------------------------------
# 3. Brancher le référentiel comme autorité de preuve dans Sector.
# ---------------------------------------------------------------------------
replace_once(
    "cyberwatch/organisation_sector.py",
    "    org_identity,\n    org_enrichment,\n    sector as sector_policy,",
    "    org_identity,\n    org_enrichment,\n    organisation_family,\n    sector as sector_policy,",
)
replace_once(
    "cyberwatch/organisation_sector.py",
    'EVIDENCE_MANUAL_REFERENCE = "manual_reference"\nEVIDENCE_STRUCTURED_SOURCE = "structured_source"',
    'EVIDENCE_MANUAL_REFERENCE = "manual_reference"\nEVIDENCE_ORGANISATION_FAMILY = "organisation_family"\nEVIDENCE_STRUCTURED_SOURCE = "structured_source"',
)
replace_once(
    "cyberwatch/organisation_sector.py",
    "STRONG_EVIDENCE_TYPES = frozenset({\n    EVIDENCE_MANUAL_REFERENCE,\n    EVIDENCE_NAF_PRECISE,\n})",
    "STRONG_EVIDENCE_TYPES = frozenset({\n    EVIDENCE_MANUAL_REFERENCE,\n    EVIDENCE_ORGANISATION_FAMILY,\n    EVIDENCE_NAF_PRECISE,\n})",
)
replace_once(
    "cyberwatch/organisation_sector.py",
    "AUDITED_EVIDENCE_TYPES: tuple[str, ...] = (\n    EVIDENCE_MANUAL_REFERENCE,\n    EVIDENCE_NAF_PRECISE,",
    "AUDITED_EVIDENCE_TYPES: tuple[str, ...] = (\n    EVIDENCE_MANUAL_REFERENCE,\n    EVIDENCE_ORGANISATION_FAMILY,\n    EVIDENCE_NAF_PRECISE,",
)
family_collector = '''\n\ndef _organisation_family_evidence(items: list[Item]):\n    \"\"\"Famille institutionnelle/syndicale versionnée, sans réseau ni LLM.\"\"\"\n    seen: set[tuple[str, str]] = set()\n    for item in items:\n        match = organisation_family.match_organisation_family(item.Organisation_Raw)\n        if match is None:\n            continue\n        marker = (item.Organisation_Key, match.family_id)\n        if marker in seen:\n            continue\n        seen.add(marker)\n        yield OrganisationSectorEvidence(\n            item.Organisation_Key, item.Organisation_Raw, match.sector,\n            EVIDENCE_ORGANISATION_FAMILY, match.confidence or \"HIGH\",\n            source=match.source, evidence_text=match.evidence_text,\n            evidence_url=match.source_url, item_id=item.Item_ID,\n        )\n'''
replace_once(
    "cyberwatch/organisation_sector.py",
    "\ndef _structured_source_evidence(items: list[Item], source_fact_rows: list[dict], policy: dict):",
    family_collector + "\n\ndef _structured_source_evidence(items: list[Item], source_fact_rows: list[dict], policy: dict):",
)
replace_once(
    "cyberwatch/organisation_sector.py",
    "    collectors = (\n        _manual_reference_evidence(reference, reference_keys),\n        _structured_source_evidence(items, source_fact_rows, policy),",
    "    collectors = (\n        _manual_reference_evidence(reference, reference_keys),\n        _organisation_family_evidence(items),\n        _structured_source_evidence(items, source_fact_rows, policy),",
)
replace_once(
    "cyberwatch/organisation_sector.py",
    "PRECEDENCE: tuple[str, ...] = (\n    EVIDENCE_MANUAL_REFERENCE,\n    EVIDENCE_NAF_PRECISE,\n    EVIDENCE_LLM_ORGANISATION,\n)",
    "PRECEDENCE: tuple[str, ...] = (\n    EVIDENCE_MANUAL_REFERENCE,\n    EVIDENCE_ORGANISATION_FAMILY,\n    EVIDENCE_NAF_PRECISE,\n    EVIDENCE_LLM_ORGANISATION,\n)",
)
replace_once(
    "cyberwatch/organisation_sector.py",
    '                    "MANUAL" if evidence.evidence_type == EVIDENCE_MANUAL_REFERENCE\n                    else "NAF" if evidence.evidence_type == EVIDENCE_NAF_PRECISE\n                    else ""\n',
    '                    "MANUAL" if evidence.evidence_type == EVIDENCE_MANUAL_REFERENCE\n                    else "REFERENCE" if evidence.evidence_type == EVIDENCE_ORGANISATION_FAMILY\n                    else "NAF" if evidence.evidence_type == EVIDENCE_NAF_PRECISE\n                    else ""\n',
)

# ---------------------------------------------------------------------------
# 4. SourceFacts : un statut accepted doit être réellement promouvable.
# ---------------------------------------------------------------------------
old_ai_activity = '''def _ai_activity(ai_result: dict, organisation: str) -> tuple[str, str]:\n    candidate = ai_result.get("activity_description") if isinstance(ai_result, dict) else None\n    if not isinstance(candidate, dict):\n        return "", ""\n    value = str(candidate.get("value") or "").strip()\n    evidence = str(candidate.get("evidence") or "").strip()\n    if not value or not evidence or searchable(organisation) not in searchable(evidence):\n        return "", ""\n    return value, evidence\n'''
new_ai_activity = '''def _activity_evidence_matches_organisation(organisation: str, evidence: str) -> bool:\n    \"\"\"Même contrat pour la validation IA et la promotion SourceFacts.\n\n    L'ancien contrôle exigeait le libellé normalisé complet dans la citation ;\n    un cache pouvait donc être `accepted` puis rejeté ici pour une variante\n    éditoriale du nom. On accepte soit le nom complet, soit un faisceau de\n    jetons distinctifs de la victime (sigle inclus), jamais une citation sans\n    rattachement identifiable.\n    \"\"\"\n    org = searchable(organisation)\n    proof = searchable(evidence)\n    if not org or not proof:\n        return False\n    if org in proof:\n        return True\n    stop = {"de", "du", "des", "la", "le", "les", "l", "d", "et", "the", "of"}\n    tokens = [token for token in org.split() if token not in stop and len(token) >= 3]\n    hits = {token for token in tokens if token in proof.split()}\n    if any(len(token) <= 5 and token.isalpha() and token.upper() == token for token in organisation.split()):\n        return bool(hits)\n    return len(hits) >= min(2, len(set(tokens))) if tokens else False\n\n\ndef _ai_activity(ai_result: dict, organisation: str) -> tuple[str, str]:\n    candidate = ai_result.get("activity_description") if isinstance(ai_result, dict) else None\n    if not isinstance(candidate, dict):\n        return "", ""\n    value = str(candidate.get("value") or "").strip()\n    evidence = str(candidate.get("evidence") or "").strip()\n    if not value or not evidence or not _activity_evidence_matches_organisation(organisation, evidence):\n        return "", ""\n    return value, evidence\n'''
replace_once("cyberwatch/source_facts.py", old_ai_activity, new_ai_activity)
replace_once(
    "cyberwatch/source_facts.py",
    '        "activity_description": "Activity_Description",\n',
    '        "activity_description": "Activity_Description",\n        "activity_sector_match": "Activity_Sector_Match",\n',
)
replace_once(
    "cyberwatch/source_facts.py",
    '    refreshable = {"Summary", "Initial_Access", "Attack_Flow_JSON", "Impact"}\n',
    '    refreshable = {"Summary", "Initial_Access", "Attack_Flow_JSON", "Impact", "Activity_Description", "Activity_Sector_Match"}\n',
)
replace_once(
    "cyberwatch/source_facts.py",
    '        "Impact": "impact",\n    }\n',
    '        "Impact": "impact",\n        "Activity_Description": "activity_description",\n        "Activity_Sector_Match": "activity_sector_match",\n    }\n',
)

replace_once(
    "cyberwatch/source_facts_ai.py",
    'PROMPT_VERSION = "2026-08-26.source-facts.14"',
    'PROMPT_VERSION = "2026-08-30.source-facts.15"',
)
replace_once(
    "cyberwatch/source_facts_ai.py",
    '    "activity_description": "activity-description-v1",',
    '    "activity_description": "activity-description-v2",',
)
replace_once(
    "cyberwatch/source_facts_ai.py",
    '    "activity_sector_match": "activity-sector-match-v4",',
    '    "activity_sector_match": "activity-sector-match-v5",',
)
replace_once(
    "cyberwatch/source_facts_ai.py",
    '''    if "activity_description" in fields:\n        fact = _normalize_fact(raw.get("activity_description"), context)\n        if fact:\n            result["activity_description"] = fact\n''',
    '''    if "activity_description" in fields:\n        fact = _normalize_fact(raw.get("activity_description"), context)\n        if fact:\n            from . import source_facts as sf\n            if sf._activity_evidence_matches_organisation(organisation, fact["evidence"]):\n                result["activity_description"] = fact\n''',
)
replace_once(
    "cyberwatch/source_facts_ai.py",
    "Même une activité associative, caritative, syndicale, politique ou cultuelle (banque alimentaire, association loi 1901, ONG, parti politique, syndicat professionnel, culte) doit recevoir le secteur professionnel le plus proche de la liste plutôt que Inconnu : choisis toujours la meilleure approximation disponible. Ne renvoie Inconnu que si activity_description est lui-même vide (rien à rapprocher).",
    "Lorsqu'une activité explicitement décrite est syndicale ou relève d'une organisation professionnelle sans activité commerciale propre, utilise Association / Syndicat. Pour les autres activités associatives, choisis le secteur correspondant à l'activité réellement décrite ; ne force jamais Services aux entreprises par défaut. Ne renvoie Inconnu que si activity_description est lui-même vide (rien à rapprocher).",
)

# ---------------------------------------------------------------------------
# 5. Télémétrie : persister une abstention LLM et la rejouer sans la réécrire.
# ---------------------------------------------------------------------------
replace_once(
    "cyberwatch/organisation_sector_llm.py",
    'PROMPT_VERSION = "2026-08-28.8"',
    'PROMPT_VERSION = "2026-08-30.9"',
)
replace_once(
    "cyberwatch/organisation_sector_llm.py",
    '    "Basis", "Reason", "Model", "Prompt_Version", "Created_At",\n]',
    '    "Basis", "Reason", "Model", "Prompt_Version", "Created_At",\n    "Decision_Status", "Execution_Status",\n]',
)
replace_once(
    "cyberwatch/organisation_sector_llm.py",
    "La taxonomie n'est pas exhaustive : n'oblige jamais une activité sociale, "
    "\n    \"caritative ou associative à entrer dans 'Services aux entreprises', qui \"\n"
    "    \"désigne exclusivement des prestations B2B. Exemple : une banque alimentaire \"\n"
    "    \"qui fournit de l'aide alimentaire reste Inconnu dans cette taxonomie. \"",
    "La taxonomie contient désormais 'Association / Syndicat' pour les organisations dont la nature syndicale/professionnelle est explicitement établie. "
    "\n    \"N'utilise jamais 'Services aux entreprises' comme catégorie par défaut pour une association, un syndicat ou une structure caritative ; ce secteur désigne exclusivement des prestations B2B. \"",
)
cache_helper_anchor = '''def _cache_by_key(rows: list[dict]) -> dict[str, dict]:\n    indexed: dict[str, dict] = {}\n    for row in rows:\n        key = org_identity.effective_organisation_key(\n            row.get("Organisation", ""), row.get("Organisation_Key", ""),\n        )\n        if not key:\n            continue\n        canonical = dict(row)\n        canonical["Organisation_Key"] = key\n        indexed[key] = canonical\n    return indexed\n'''
cache_helper_new = cache_helper_anchor + '''\n\ndef _cached_decision_outcome(row: dict) -> str:\n    \"\"\"Restaure la décision métier indépendamment de l'état du runtime.\"\"\"\n    status = str(row.get("Decision_Status") or "").strip().upper()\n    if status == "ABSTAINED":\n        return "NO_MATCH"\n    if status == "PRODUCED":\n        return "PRODUCED"\n    # Compatibilité avec les caches historiques qui ne stockaient que les\n    # décisions positives et ne possédaient pas encore Decision_Status.\n    sector = str(row.get("Sector") or "").strip()\n    if sector in config.SECTORS and sector != config.SECTOR_UNKNOWN:\n        return "PRODUCED"\n    return ""\n'''
replace_once("cyberwatch/organisation_sector_llm.py", cache_helper_anchor, cache_helper_new)
replace_once(
    "cyberwatch/organisation_sector_llm.py",
    '''        if not force and cached is not None and cached.get("Input_Hash") == input_hash:\n            report.cache_hits += 1\n            report.outcomes[key] = "PRODUCED"\n            continue\n''',
    '''        cached_outcome = _cached_decision_outcome(cached or {})\n        if not force and cached is not None and cached.get("Input_Hash") == input_hash and cached_outcome:\n            report.cache_hits += 1\n            report.outcomes[key] = cached_outcome\n            if cached_outcome == "NO_MATCH":\n                report.abstentions += 1\n            continue\n''',
)
replace_once(
    "cyberwatch/organisation_sector_llm.py",
    '''                if candidate is None:\n                    report.abstentions += 1\n                    report.outcomes[key] = "NO_MATCH"\n                    continue\n''',
    '''                if candidate is None:\n                    report.abstentions += 1\n                    report.outcomes[key] = "NO_MATCH"\n                    context = next(context for pending_key, context, _hash in pending if pending_key == key)\n                    updated_rows[key] = {\n                        "Organisation_Key": key,\n                        "Organisation": context.organisation,\n                        "Input_Hash": hash_by_key.get(key, ""),\n                        "Sector": "",\n                        "Confidence": "",\n                        "Basis": "insufficient",\n                        "Reason": "Abstention LLM : aucune décision sectorielle publiable pour ce contexte.",\n                        "Model": effective_model,\n                        "Prompt_Version": prompt_version,\n                        "Created_At": now,\n                        "Decision_Status": "ABSTAINED",\n                        "Execution_Status": "EXECUTED",\n                    }\n                    continue\n''',
)
replace_once(
    "cyberwatch/organisation_sector_llm.py",
    '''                    "Prompt_Version": prompt_version,\n                    "Created_At": now,\n                }\n''',
    '''                    "Prompt_Version": prompt_version,\n                    "Created_At": now,\n                    "Decision_Status": "PRODUCED",\n                    "Execution_Status": "EXECUTED",\n                }\n''',
)

# ---------------------------------------------------------------------------
# 6. Tests ciblés : familles, contre-exemples, propagation, replay outcomes.
# ---------------------------------------------------------------------------
(ROOT / "tests" / "test_organisation_family.py").write_text(r'''from __future__ import annotations

import pytest

from cyberwatch import config, organisation_family


@pytest.mark.parametrize(("name", "family", "sector"), [
    ("SDIS de la Moselle", "FR_SDIS", config.SECTOR_ADMIN),
    ("SDIS 57", "FR_SDIS", config.SECTOR_ADMIN),
    ("Service départemental d’incendie et de secours de la Moselle", "FR_SDIS", config.SECTOR_ADMIN),
    ("ARS Bretagne", "FR_ARS", config.SECTOR_HEALTH),
    ("Agence régionale de santé de La Réunion", "FR_ARS", config.SECTOR_HEALTH),
    ("CHU de Lille", "FR_CHU", config.SECTOR_HEALTH),
    ("CROUS de Lyon", "FR_CROUS", config.SECTOR_EDUCATION),
    ("Préfecture de la Moselle", "FR_PREFECTURE", config.SECTOR_ADMIN),
    ("Communauté d'agglomération du Grand Annecy", "FR_INTERCOMMUNALITY", config.SECTOR_ADMIN),
    ("CGT Éduc’Action Créteil", "FR_TRADE_UNION", config.SECTOR_ASSOCIATION),
    ("CFDT Santé Sociaux", "FR_TRADE_UNION", config.SECTOR_ASSOCIATION),
    ("Force ouvrière", "FR_TRADE_UNION", config.SECTOR_ASSOCIATION),
    ("Syndicat professionnel des métiers du numérique", "FR_PROFESSIONAL_UNION", config.SECTOR_ASSOCIATION),
    ("France Travail", "FR_FRANCE_TRAVAIL", config.SECTOR_ADMIN),
    ("ANSSI", "FR_ANSSI", config.SECTOR_ADMIN),
])
def test_reference_family_matches(name, family, sector):
    match = organisation_family.match_organisation_family(name)
    assert match is not None
    assert match.family_id == family
    assert match.sector == sector
    assert match.confidence == "HIGH"


@pytest.mark.parametrize("name", [
    "SDIS Consulting",
    "ARS Technologies",
    "CGT Solutions",
    "CAF Digital",
    "CMA Consulting",
    "Sud Ouest",
])
def test_reference_family_rejects_commercial_or_ambiguous_lookalikes(name):
    assert organisation_family.match_organisation_family(name) is None


def test_reference_is_well_formed():
    assert organisation_family.validate_reference() == []
    assert config.SECTOR_ASSOCIATION in config.SECTORS
''', encoding="utf-8")

(ROOT / "tests" / "test_source_facts_promotion_contract.py").write_text(r'''from __future__ import annotations

from cyberwatch import source_facts as sf
from cyberwatch import source_facts_ai as sfa


def test_activity_evidence_accepts_editorial_variant_of_victim_name():
    assert sf._activity_evidence_matches_organisation(
        "CGT Éduc’Action Créteil",
        "La CGT Éduc’Action de l’académie de Créteil représente les personnels de l'éducation.",
    )
    assert sf._activity_evidence_matches_organisation(
        "SDIS de la Moselle",
        "Le SDIS 57 est le service départemental d’incendie et de secours de la Moselle.",
    )
    assert not sf._activity_evidence_matches_organisation(
        "SDIS de la Moselle",
        "Une entreprise spécialisée dans les services informatiques.",
    )


def test_semantic_promotion_gap_couvre_activity_sector_match():
    semantic = sfa.SemanticExtraction(
        item_id="ITM-x",
        content_hash="hash",
        fields={
            "activity_description": {"value": "organisation syndicale", "evidence": "CGT, organisation syndicale"},
            "activity_sector_match": {"value": "Association / Syndicat", "evidence": "CGT, organisation syndicale"},
        },
        statuses={"activity_description": "accepted", "activity_sector_match": "accepted"},
    )
    fact = {"Activity_Description": "organisation syndicale", "Activity_Sector_Match": "", "Source_Metadata_JSON": ""}
    assert sf.semantic_promotion_gaps(fact, semantic) == ["activity_sector_match"]


def test_merge_can_clear_stale_activity_after_semantic_abstention():
    old = [{
        "Item_ID": "ITM-x",
        "Activity_Description": "ancienne activité",
        "Activity_Sector_Match": "Services aux entreprises",
        "Source_Metadata_JSON": sf._dumps_json({"_source_facts_content_hash": "old"}),
    }]
    new = [{
        "Item_ID": "ITM-x",
        "Source_Metadata_JSON": sf._dumps_json({
            "_source_facts_content_hash": "new",
            "_source_facts_semantic_status": {
                "activity_description": "abstained",
                "activity_sector_match": "abstained",
            },
        }),
    }]
    merged = sf.merge_source_facts(old, new)[0]
    assert merged["Activity_Description"] == ""
    assert merged["Activity_Sector_Match"] == ""
''', encoding="utf-8")

(ROOT / "tests" / "test_organisation_sector_llm_outcomes.py").write_text(r'''from __future__ import annotations

from cyberwatch import organisation_sector_llm as osllm


def test_legacy_positive_cache_is_still_produced():
    assert osllm._cached_decision_outcome({"Sector": "Santé"}) == "PRODUCED"


def test_persisted_abstention_replays_as_no_match_not_budget_blocked():
    row = {
        "Sector": "",
        "Decision_Status": "ABSTAINED",
        "Execution_Status": "EXECUTED",
    }
    assert osllm._cached_decision_outcome(row) == "NO_MATCH"


def test_empty_unexecuted_cache_has_no_decision():
    assert osllm._cached_decision_outcome({"Decision_Status": "", "Execution_Status": "BUDGET_BLOCKED"}) == ""
''', encoding="utf-8")

# ---------------------------------------------------------------------------
# 7. Documentation de la nouvelle source de vérité.
# ---------------------------------------------------------------------------
append_once(
    "METHODOLOGY.md",
    "### Référentiel déterministe des familles d’organisations",
    '''### Référentiel déterministe des familles d’organisations\n\nLa qualification `Sector` dispose d'un canal `organisation_family` versionné dans `reference/organisation_families.csv`. Il couvre les familles institutionnelles et organisationnelles dont le nom complet ou le sigle constitue une preuve auto-descriptive : SDIS, préfectures, ministères, collectivités, CCAS/CIAS, organismes sociaux, ARS, établissements hospitaliers, CROUS/rectorats, juridictions, opérateurs publics et organisations syndicales connues.\n\nLa préséance est : override manuel → famille organisationnelle déterministe → NAF officiel précis → décision LLM finale. Une correspondance de famille est `HIGH`, auditée avec sa provenance et ne consomme aucun appel LLM. Les sigles ne sont jamais cherchés comme de simples sous-chaînes : leur mode de correspondance et les contre-exemples commerciaux sont testés.\n\nSourceFacts applique désormais le même contrat de rattachement de l'activité à la victime au moment de l'acceptation et au moment de la promotion. Un statut sémantique `accepted` ne peut donc plus masquer une valeur vide publiée. Les abstentions de secteur LLM sont persistées avec `Decision_Status=ABSTAINED` et `Execution_Status=EXECUTED`, afin qu'un replay sans budget conserve `NO_MATCH` au lieu de réécrire l'histoire en `BUDGET_BLOCKED`.''',
)

print("organisation reference hardening applied")
