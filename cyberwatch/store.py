"""Lecture et écriture de la base : cinq CSV canoniques + sorties JSON.

Les CSV sont écrits de façon atomique et avec un ordre de colonnes figé, afin
que chaque run produise un diff git lisible plutôt qu'un remaniement complet.
"""

from __future__ import annotations

import csv
import json
import os
import tempfile
from pathlib import Path

from .model import (
    AI_QUALIFICATIONS_COLUMNS,
    AI_USAGE_COLUMNS,
    ENTITY_WATCH_COLUMNS,
    INCIDENT_COLUMNS,
    ITEM_COLUMNS,
    RUN_LOG_COLUMNS,
    RUN_SOURCE_COLUMNS,
    SOURCE_COLUMNS,
    Incident,
    Item,
)

# Racine du dépôt, déduite de l'emplacement du paquet.
ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
#: Données du dashboard. Le site est servi depuis la racine du dépôt, afin
#: que l'URL de GitHub Pages soit celle du dashboard sans sous-dossier.
SITE_DATA_DIR = ROOT / "assets" / "data"

ITEMS_CSV = DATA_DIR / "items.csv"
INCIDENTS_CSV = DATA_DIR / "incidents.csv"
SOURCES_CSV = DATA_DIR / "sources.csv"
RUN_SOURCES_CSV = DATA_DIR / "run_sources.csv"
RUN_LOG_CSV = DATA_DIR / "run_log.csv"
ENTITY_WATCH_CSV = DATA_DIR / "entity_watch.csv"
ENRICHMENT_REFERENCE_CSV = DATA_DIR / "enrichment_reference.csv"
AI_QUALIFICATIONS_CSV = DATA_DIR / "ai_qualifications.csv"
AI_USAGE_CSV = DATA_DIR / "ai_usage.csv"
SNAPSHOT_JSON = DATA_DIR / "snapshot.json"
BASELINE_JSON = DATA_DIR / "baseline.json"

BASE_UNINITIALIZED = "UNINITIALIZED"
BASE_VALID = "VALID"
BASE_INCOHERENT = "INCOHERENT"


# --------------------------------------------------------------------------
# Primitives CSV
# --------------------------------------------------------------------------


def write_csv(path: Path, columns: list[str], rows: list[dict]) -> None:
    """Écrit un CSV de façon atomique, colonnes dans l'ordre canonique.

    L'écriture passe par un fichier temporaire puis un `replace` : un run
    interrompu ne peut pas laisser une base tronquée.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w", delete=False, dir=path.parent, encoding="utf-8", newline=""
    )
    try:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({col: row.get(col, "") for col in columns})
        handle.close()
        # Les fichiers temporaires naissent en 0600 ; la base est publique.
        os.chmod(handle.name, 0o644)
        os.replace(handle.name, path)
    except Exception:
        handle.close()
        Path(handle.name).unlink(missing_ok=True)
        raise


def read_csv(path: Path) -> list[dict]:
    """Lit un CSV, ou renvoie une liste vide si le fichier n'existe pas."""
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def write_json(path: Path, payload) -> None:
    """Écrit un JSON compact et déterministe (clés triées) de façon atomique."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w", delete=False, dir=path.parent, encoding="utf-8"
    )
    try:
        json.dump(payload, handle, ensure_ascii=False, sort_keys=True, indent=1)
        handle.write("\n")
        handle.close()
        # Les fichiers temporaires naissent en 0600 ; la base est publique.
        os.chmod(handle.name, 0o644)
        os.replace(handle.name, path)
    except Exception:
        handle.close()
        Path(handle.name).unlink(missing_ok=True)
        raise


# --------------------------------------------------------------------------
# Accès typés aux jeux de données
# --------------------------------------------------------------------------


def load_items(path: Path | None = None) -> list[Item]:
    return [Item.from_row(row) for row in read_csv(path or ITEMS_CSV)]


def save_items(items: list[Item], path: Path | None = None) -> None:
    write_csv(path or ITEMS_CSV, ITEM_COLUMNS, [item.to_row() for item in items])


def load_incidents(path: Path | None = None) -> list[Incident]:
    return [Incident.from_row(row) for row in read_csv(path or INCIDENTS_CSV)]


def save_incidents(incidents: list[Incident], path: Path | None = None) -> None:
    write_csv(
        path or INCIDENTS_CSV,
        INCIDENT_COLUMNS,
        [incident.to_row() for incident in incidents],
    )


def save_sources(rows: list[dict], path: Path | None = None) -> None:
    write_csv(path or SOURCES_CSV, SOURCE_COLUMNS, rows)


def load_sources(path: Path | None = None) -> list[dict]:
    return read_csv(path or SOURCES_CSV)


def append_run_sources(rows: list[dict], path: Path | None = None) -> None:
    """Ajoute les lignes du run courant à l'historique `RUN_SOURCES`."""
    target = path or RUN_SOURCES_CSV
    write_csv(target, RUN_SOURCE_COLUMNS, read_csv(target) + rows)


def append_run_log(row: dict, path: Path | None = None) -> None:
    """Ajoute la synthèse du run courant à l'historique `RUN_LOG`."""
    target = path or RUN_LOG_CSV
    write_csv(target, RUN_LOG_COLUMNS, read_csv(target) + [row])


def save_entity_watch(rows: list[dict], path: Path | None = None) -> None:
    write_csv(path or ENTITY_WATCH_CSV, ENTITY_WATCH_COLUMNS, rows)


def load_entity_watch(path: Path | None = None) -> list[dict]:
    return read_csv(path or ENTITY_WATCH_CSV)


def load_run_sources(path: Path | None = None) -> list[dict]:
    return read_csv(path or RUN_SOURCES_CSV)


def load_ai_qualifications(path: Path | None = None) -> list[dict]:
    return read_csv(path or AI_QUALIFICATIONS_CSV)


def save_ai_qualifications(rows: list[dict], path: Path | None = None) -> None:
    write_csv(path or AI_QUALIFICATIONS_CSV, AI_QUALIFICATIONS_COLUMNS, rows)


def append_ai_usage(row: dict, path: Path | None = None) -> None:
    """Ajoute la synthèse d'usage IA du run courant à l'historique `AI_USAGE`."""
    target = path or AI_USAGE_CSV
    write_csv(target, AI_USAGE_COLUMNS, read_csv(target) + [row])


def load_run_log(path: Path | None = None) -> list[dict]:
    return read_csv(path or RUN_LOG_CSV)


def load_snapshot(path: Path | None = None) -> dict:
    target = path or SNAPSHOT_JSON
    if not target.exists():
        return {}
    try:
        with target.open(encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def save_snapshot(payload: dict, path: Path | None = None) -> None:
    write_json(path or SNAPSHOT_JSON, payload)


def load_baseline(path: Path | None = None) -> dict:
    target = path or BASELINE_JSON
    if not target.exists():
        return {}
    with target.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    return payload if isinstance(payload, dict) else {}


def save_baseline(payload: dict, path: Path | None = None) -> None:
    write_json(path or BASELINE_JSON, payload)


def snapshot_state() -> tuple[str, list[str]]:
    """Détermine si le corpus publié est absent, valide ou incohérent.

    Une base neuve n'est pas une corruption : aucun des trois fichiers de
    snapshot n'existe. Dès qu'un seul existe, les trois et leur provenance
    doivent être cohérents.
    """
    required = {
        "data/snapshot.json": SNAPSHOT_JSON,
        "data/items.csv": ITEMS_CSV,
        "data/incidents.csv": INCIDENTS_CSV,
    }
    present = {name: path.exists() for name, path in required.items()}
    if not any(present.values()):
        # Un run BROKEN peut laisser des journaux de diagnostic sans constituer
        # un snapshot. Seul un run déclaré OK sans snapshot est incohérent.
        if any(row.get("Overall_Status") == "OK" for row in load_run_log()):
            return BASE_INCOHERENT, [
                "RUN_LOG indique un run OK mais aucun snapshot courant n'existe"
            ]
        return BASE_UNINITIALIZED, []

    problems = [f"{name} absent" for name, exists in present.items() if not exists]
    if problems:
        return BASE_INCOHERENT, problems

    snapshot = load_snapshot()
    if not snapshot:
        return BASE_INCOHERENT, ["data/snapshot.json est illisible ou vide"]

    # Import local : store reste le seul module responsable des fichiers et
    # n'impose pas identity à l'import du paquet.
    from . import identity

    items = load_items()
    incidents = load_incidents()
    actual = {
        "Items_Count": len(items),
        "Incidents_Count": len(incidents),
        "Items_Hash": identity.items_hash(items),
        "Incidents_Hash": identity.incidents_hash(incidents),
    }
    for key, value in actual.items():
        if str(snapshot.get(key, "")) != str(value):
            problems.append(f"provenance snapshot incohérente : {key}")
    return (BASE_VALID if not problems else BASE_INCOHERENT), problems
