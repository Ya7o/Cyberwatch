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


def load_run_log(path: Path | None = None) -> list[dict]:
    return read_csv(path or RUN_LOG_CSV)
