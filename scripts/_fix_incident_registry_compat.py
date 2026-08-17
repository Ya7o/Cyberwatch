#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def patch(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"pattern not found in {path}: {old[:120]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


patch(
    "cyberwatch/store.py",
    "def load_incident_id_registry(path: Path | None = None) -> list[dict]:\n"
    "    return read_csv(path or INCIDENT_ID_REGISTRY_CSV)\n\n\n"
    "def save_incident_id_registry(rows: list[dict], path: Path | None = None) -> None:\n"
    "    ordered = sorted(rows, key=lambda row: (row.get('Incident_ID', ''), row.get('Anchor_Item_ID', '')))\n"
    "    write_csv(path or INCIDENT_ID_REGISTRY_CSV, REGISTRY_COLUMNS, ordered)\n",
    "def _incident_registry_path(path: Path | None = None) -> Path:\n"
    "    if path is not None:\n"
    "        return path\n"
    "    # Suivre le répertoire du snapshot courant. Les tests et outils qui\n"
    "    # isolent ITEMS_CSV obtiennent ainsi automatiquement un registre isolé,\n"
    "    sans risque d'écrire dans data/ réel. En production, ce chemin reste\n"
    "    exactement data/incident_id_registry.csv.\n"
    "    return ITEMS_CSV.parent / INCIDENT_ID_REGISTRY_CSV.name\n\n\n"
    "def load_incident_id_registry(path: Path | None = None) -> list[dict]:\n"
    "    return read_csv(_incident_registry_path(path))\n\n\n"
    "def save_incident_id_registry(rows: list[dict], path: Path | None = None) -> None:\n"
    "    ordered = sorted(rows, key=lambda row: (row.get('Incident_ID', ''), row.get('Anchor_Item_ID', '')))\n"
    "    write_csv(_incident_registry_path(path), REGISTRY_COLUMNS, ordered)\n",
)

patch(
    "cyberwatch/cli.py",
    "    problems = pre_export_checks(items, incidents, [])\n"
    "    problems.extend(incident_identity.validate_registry(\n"
    "        store.load_incident_id_registry(), items, incidents\n"
    "    ))\n"
    "    # Les contrôles portant sur RUN_SOURCES ne s'appliquent pas hors run.\n",
    "    problems = pre_export_checks(items, incidents, [])\n"
    "    registry = store.load_incident_id_registry()\n"
    "    if not registry and incidents:\n"
    "        # Compatibilité de migration : un snapshot antérieur au registre\n"
    "        # reste vérifiable uniquement si chaque ID publié permet de retrouver\n"
    "        # son ancre de manière exacte et non ambiguë. Rien n'est écrit ici.\n"
    "        try:\n"
    "            registry = incident_identity.bootstrap_registry(items, incidents)\n"
    "        except ValueError as error:\n"
    "            problems.append(f'Registre Incident_ID non migrable : {error}')\n"
    "    problems.extend(incident_identity.validate_registry(registry, items, incidents))\n"
    "    # Les contrôles portant sur RUN_SOURCES ne s'appliquent pas hors run.\n",
)

print("incident registry compatibility fix applied")
