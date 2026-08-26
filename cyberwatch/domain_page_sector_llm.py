"""Fallback LLM sur le texte déjà scrappé par domain_page_sector.py.

Se déclenche uniquement quand le classificateur déterministe
(:func:`cyberwatch.context_sector.classify_explicit_activity`) a échoué à
classer le titre/meta-description d'une page officielle déjà récupérée
(``Status == NO_EVIDENCE`` avec un texte non vide). Jamais un second accès
réseau : ce module relit uniquement ``data/organisation_domain_page.csv``
et complète en place les lignes que le passage déterministe n'a pas su
classer, exactement comme :mod:`cyberwatch.organisation_sector_llm` complète
``organisation_sector.py`` sans jamais y accéder au réseau lui-même.

Contrat de sortie identique à celui de ``source_facts_ai.py`` (audit
2026-08-26, cohérence des deux canaux plutôt qu'un contrat inventé ici) :
``activity_description`` puis ``activity_sector_match``, tous deux ancrés
par une preuve extraite du texte fourni. Une valeur non ancrée dans le texte
de la page est rejetée — même discipline anti-hallucination que
``source_facts_ai._normalize_fact``.

Étape automatique de ``create``/``maj`` pour les pages applicables, et
réutilisable explicitement via la commande ``domain-page-llm``. ``replay``
reste cache-only et ne l'appelle jamais.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import config, domain_page_sector as dps, llm_runtime, store
from .normalize import searchable

TASK = "domain_page_sector"
PROMPT_VERSION = "2026-08-26.2"
DEFAULT_BATCH_SIZE = 20
MAX_OUTPUT_TOKENS = 800
MAX_TEXT_CHARS = dps.MAX_TEXT_CHARS

_SCHEMA_NAME = "cyberwatch_domain_page_sector"

SYSTEM_PROMPT = (
    "Tu classes l'activité d'une organisation à partir du titre et de la "
    "meta-description de sa page officielle, déjà extraits ci-dessous.\n"
    "Tu n'as accès à rien d'autre : pas de recherche web, pas de "
    "connaissance externe sur l'organisation.\n"
    "activity_description décrit en quelques mots l'activité affichée par la "
    "page, seulement si le texte fourni la présente explicitement ; sa preuve "
    "doit être une citation exacte du texte fourni.\n"
    "activity_sector_match reprend cette activité et choisis, parmi le "
    "secteur de la liste fournie, celui qui s'en rapproche le plus. Même une "
    "activité associative, caritative, syndicale, politique ou cultuelle "
    "doit recevoir le secteur professionnel le plus proche plutôt que "
    "Inconnu : choisis toujours la meilleure approximation disponible. Ne "
    "renvoie Inconnu que si le texte fourni est un argumentaire commercial "
    "trop générique pour établir la moindre activité.\n"
    "Si le titre et la meta-description ne permettent d'établir aucune "
    "activité du tout, laisse les deux champs vides plutôt que de deviner "
    "sans texte source."
)


def _fact_schema() -> dict:
    return {
        "type": "object",
        "properties": {
            "value": {"type": "string"},
            "confidence": {"type": "number"},
            "evidence": {"type": "string"},
        },
        "required": ["value", "confidence", "evidence"],
        "additionalProperties": False,
    }


def _schema() -> dict:
    sector_fact = _fact_schema()
    sector_fact = {
        **sector_fact,
        "properties": {**sector_fact["properties"], "value": {"type": "string", "enum": [*config.SECTORS]}},
    }
    return {
        "type": "object",
        "properties": {
            "activity_description": _fact_schema(),
            "activity_sector_match": sector_fact,
        },
        "required": ["activity_description", "activity_sector_match"],
        "additionalProperties": False,
    }


def _grounded(evidence: str, context: str) -> bool:
    needle = searchable(evidence)
    return bool(needle) and needle in searchable(context)


def _page_text(row: dict) -> str:
    """Le même texte que celui déjà passé au classificateur déterministe."""
    return " ".join(part for part in (row.get("Page_Description", ""), row.get("Page_Title", "")) if part)[:MAX_TEXT_CHARS * 2]


def select_rows_for_llm(cache_rows: list[dict]) -> list[dict]:
    """Lignes fetchées avec succès mais non classées par le canal déterministe.

    Exclut : les lignes déjà résolues (``Activity_Sector_Match`` non vide,
    quelle que soit l'origine), celles jamais fetchées (garde d'identité
    échouée ou page injoignable — rien à ancrer un appel LLM dessus), et
    celles sans aucun texte exploitable.
    """
    selected = []
    for row in cache_rows:
        if (row.get("Activity_Sector_Match") or "").strip():
            continue
        if row.get("Status") != dps.STATUS_NO_EVIDENCE:
            continue
        if not _page_text(row):
            continue
        selected.append(row)
    return sorted(selected, key=lambda row: row.get("Organisation_Key", ""))


@dataclass(frozen=True)
class DomainPageLlmCandidate:
    activity_description: str
    activity_sector_match: str


def _validate(raw: dict, context: str) -> DomainPageLlmCandidate | None:
    if not isinstance(raw, dict):
        return None
    activity = raw.get("activity_description")
    sector_match = raw.get("activity_sector_match")
    if not isinstance(activity, dict) or not isinstance(sector_match, dict):
        return None

    activity_value = str(activity.get("value") or "").strip()
    activity_evidence = str(activity.get("evidence") or "").strip()
    if not activity_value or not activity_evidence or not _grounded(activity_evidence, context):
        return None

    sector_value = str(sector_match.get("value") or "").strip()
    sector_evidence = str(sector_match.get("evidence") or "").strip()
    if (
        not sector_value
        or sector_value not in config.SECTORS
        or sector_value == config.SECTOR_UNKNOWN
        or not sector_evidence
        or not _grounded(sector_evidence, context)
    ):
        return None

    return DomainPageLlmCandidate(activity_value, sector_value)


def call_llm_for_row(row: dict) -> DomainPageLlmCandidate | None:
    context = _page_text(row)
    result = llm_runtime.runtime().call_json(
        task=TASK,
        system_prompt=SYSTEM_PROMPT,
        user_content=json.dumps({"page_title": row.get("Page_Title", ""), "page_description": row.get("Page_Description", "")}, ensure_ascii=False, sort_keys=True),
        schema_name=_SCHEMA_NAME,
        schema=_schema(),
        max_output_tokens=MAX_OUTPUT_TOKENS,
    )
    return _validate(result.data, context)


# --------------------------------------------------------------------------
# Orchestration — seule porte d'entrée réseau/LLM de ce module
# --------------------------------------------------------------------------


@dataclass
class DomainPageLlmReport:
    rows_selected: int = 0
    calls: int = 0
    resolved: int = 0
    abstentions: int = 0
    llm_available: bool = False
    dry_run: bool = False
    cost_usd: float = 0.0
    cache_rows: list[dict] = field(default_factory=list)


def enrich_domain_page_sectors(
    *,
    cache_rows: list[dict] | None = None,
    limit: int | None = None,
    dry_run: bool = False,
    force: bool = False,
    persist: bool = True,
) -> DomainPageLlmReport:
    """Complète par LLM les lignes NO_EVIDENCE de ``organisation_domain_page.csv``.

    ``force=True`` : redemande un candidat même pour une ligne déjà marquée
    ``Extraction_Source=llm`` (mais toujours pas ``Activity_Sector_Match``
    résolu — jamais une ligne déjà classée, forte ou faible).
    """
    all_rows = list(cache_rows) if cache_rows is not None else dps.load_cache()
    by_key = {row.get("Organisation_Key", ""): dict(row) for row in all_rows if row.get("Organisation_Key")}

    candidates = select_rows_for_llm(list(by_key.values()))
    if not force:
        # Une abstention n'est jamais redemandée automatiquement (même
        # discipline que ai.py._escalate_sector_llm : "llm_declined" bloque
        # les tentatives suivantes) — seul --force-llm force une nouvelle
        # question, jamais une boucle silencieuse de budget.
        candidates = [row for row in candidates if row.get("Extraction_Source") not in ("llm", "llm_declined")]
    if limit is not None:
        candidates = candidates[:limit]

    report = DomainPageLlmReport(
        rows_selected=len(candidates),
        llm_available=llm_runtime.runtime().enabled,
        dry_run=dry_run,
    )

    if not dry_run and candidates and llm_runtime.runtime().enabled:
        now = datetime.now(timezone.utc).isoformat()
        for row in candidates:
            key = row.get("Organisation_Key", "")
            try:
                candidate = call_llm_for_row(row)
            except llm_runtime.LlmBudgetExceeded:
                break
            except llm_runtime.LlmError:
                report.abstentions += 1
                continue
            report.calls += 1
            updated = dict(row)
            updated["Fetched_At"] = row.get("Fetched_At", now)
            if candidate is None:
                report.abstentions += 1
                # Statut inchangé (NO_EVIDENCE) : l'abstention reste
                # traçable, jamais une fausse réussite silencieuse.
                updated["Extraction_Source"] = "llm_declined"
            else:
                report.resolved += 1
                updated["Status"] = dps.STATUS_MATCHED
                updated["Activity_Description"] = candidate.activity_description
                updated["Activity_Sector_Match"] = candidate.activity_sector_match
                updated["Extraction_Source"] = "llm"
            by_key[key] = updated

    report.cost_usd = llm_runtime.runtime().stats.by_task.get(TASK, {}).get("estimated_cost_usd", 0.0)
    report.cache_rows = sorted(by_key.values(), key=lambda row: row.get("Organisation_Key", ""))
    if persist and not dry_run and report.calls:
        dps.save_cache(report.cache_rows)
    return report
