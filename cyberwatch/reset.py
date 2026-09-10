"""Remise à zéro explicite du corpus, sans collecte ni appel LLM."""

from __future__ import annotations

import datetime as dt
import os
import shutil
from pathlib import Path

from . import llm_runtime, source_facts_ai_runtime, store
from .runner_support import save_snapshot_provenance


# Liste fermée : les sources, référentiels, alias éditoriaux et corrections
# manuelles restent disponibles pour la prochaine collecte.
GENERATED_FILES = (
    "items.csv", "incidents.csv", "source_facts.csv", "sector_resolution.csv",
    "incident_id_registry.csv", "incident_dedup_registry.csv",
    "entity_watch.csv",
    "run_log.csv", "run_sources.csv", "production_metrics.csv",
    "snapshot.json", "baseline.json", "dedup_ai_daily_cache.csv",
    "dedup_ai_daily_usage.csv", "dedup_review_latest.json", "dedup_review_queue.json",
    "source_facts_ai_cache.json", "source_facts_ai_trace.json",
    "source_facts_ai_contexts.json", "source_facts_ai_usage.json",
    "source_facts_retry_queue.json", "cyberattaque_semantic_cache.json",
    "llm_usage.json", "performance_runs.json", "august_quality_audit.json",
    "editorial_repair_report.json", "qualification_repair_report.json",
    "sector_dedup_backfill_report.json", "sector_repair_report.json",
)

RUNTIME_PATH_OPTIONS = (
    "SOURCE_FACTS_AI_CACHE_PATH", "SOURCE_FACTS_AI_STATS_PATH",
    "SOURCE_FACTS_RETRY_QUEUE_PATH", "CYBERATTAQUE_SEMANTIC_CACHE_PATH",
    "LLM_USAGE_PATH", "CYBERWATCH_PERFORMANCE_LOG_PATH",
)


def purge() -> None:
    """Efface l'état collecté et écrit un snapshot vide valide et vérifiable.

    Les suppressions ciblent uniquement les artefacts connus du répertoire
    canonique. Une seconde purge est sans effet sur les référentiels.
    """
    root = store.DATA_DIR.resolve()
    paths = [root / name for name in (*GENERATED_FILES, "llm_runs")]
    paths.extend(Path(value) for key in RUNTIME_PATH_OPTIONS if (value := os.getenv(key)))
    # Vérifier tous les chemins avant la première suppression, y compris les
    # liens symboliques : aucun artefact ne peut viser un fichier hors de data/.
    for path in paths:
        if path.resolve() == root or not path.resolve().is_relative_to(root):
            raise ValueError(f"Chemin de purge hors de data/ : {path.name}")
        if path.is_dir() and path != root / "llm_runs":
            raise ValueError(f"Un fichier était attendu : {path.name}")
    source_facts_ai_runtime.reset_runtime()
    llm_runtime.reset_runtime()
    for path in paths:
        if path.is_symlink():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)
    store.save_items([])
    store.save_incidents([])
    save_snapshot_provenance(
        [], [], operation="PURGE", mode="PURGE",
        as_of=dt.datetime.now(dt.timezone.utc).isoformat(),
    )
