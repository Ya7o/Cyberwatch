"""Reconstitue l'état audité `RUN-20260910T072351` dans un répertoire isolé.

Le run audité n'a jamais été commité : ses deux nouvelles observations, leurs
faits et ses deux fiches n'existent que dans
`audit/latest_collection_2026-09-10/run_snapshot.json`. Ce module les recolle au
corpus canonique dans un répertoire de travail, sans jamais écrire dans `data/`
ni dans `assets/data/`.

Il sert de base commune aux régressions de reprise ciblée et à la production du
rapport de réparation livré en revue.
"""
from __future__ import annotations

import csv
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cyberwatch import model, store  # noqa: E402

AUDIT = ROOT / "audit" / "latest_collection_2026-09-10"
SNAPSHOT = AUDIT / "run_snapshot.json"

FRENCHBREACHES_ITEM = "ITM-0c085da888611a12"
CYBERATTAQUE_ITEM = "ITM-f2c9b54af4eae1da"
SURVIVING_INCIDENT = "INC-AF70EBB0A692"
REDIRECTED_INCIDENT = "INC-F7E0A7E8A73F"

FRENCHBREACHES_URL = "https://frenchbreaches.com/alertes/ville-du-tampon-mtu8oc7tsqxl3kzgkvm"
CYBERATTAQUE_URL = (
    "https://www.cyberattaque.org/le-tampon-une-cyberattaque-frappe-la-mairie-"
    "et-perturbe-fortement-les-services-municipaux/"
)

#: Référentiels recopiés tels quels : ils ne sont pas modifiés par la reprise.
_COPIED = (
    "enrichment_reference.csv", "organisation_identity_registry.csv",
    "organisation_aliases.csv", "incident_dedup_registry.csv",
    "editorial_corrections.json", "sources.csv", "territorial_identities.csv",
)

#: Libellés d'incident que le corpus courant n'a pas encore alignés sur le
#: registre d'identité. Ils sont sans rapport avec la reprise du Tampon : la
#: base de départ les fige canoniques pour que le périmètre testé ne porte que
#: sur les deux observations visées.
_CANONICAL_LABELS = {"PassPass": "Pass Pass", "Répar'Store": "Répar’stores"}

REGISTRY_COLUMNS = ["Incident_ID", "Anchor_Item_ID", "Organisation_Key", "Redirect_To"]


def available() -> bool:
    return SNAPSHOT.exists()


def _write_csv(path: Path, columns: list[str], rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({column: str(row.get(column, "") or "") for column in columns})


def _audited_incidents() -> list[dict]:
    stamp = "2026-09-10T07:23:51.799155+04:00"
    return [
        {"Incident_ID": SURVIVING_INCIDENT, "Date": "2026-09-09", "Date_Basis": "PUBLICATION",
         "Organisation": "Ville du Tampon", "Secteur": "Inconnu", "Menace": "Fuite de données",
         "Localisation": "La Réunion", "Sources": "FRENCHBREACHES",
         "Source_URLs": FRENCHBREACHES_URL, "Items_Count": "1",
         "First_seen": stamp, "Last_seen": stamp},
        {"Incident_ID": REDIRECTED_INCIDENT, "Date": "2026-09-09", "Date_Basis": "PUBLICATION",
         "Organisation": "Le Tampon", "Secteur": "Administration / Collectivité",
         "Menace": "Ransomware", "Localisation": "La Réunion", "Sources": "CYBERATTAQUE_ORG",
         "Source_URLs": CYBERATTAQUE_URL, "Items_Count": "1",
         "First_seen": stamp, "Last_seen": stamp},
    ]


def _audited_facts(payload: dict) -> list[dict]:
    """Faits audités, complétés du texte que l'audit a lui-même figé.

    Ces lignes sont antérieures au contrat de contexte éditorial. Sans ce texte,
    aucune reprise ne peut appliquer les règles de réserve à des faits produits
    par une passe fautive : c'est bien la preuve figée, jamais une version
    rechargée depuis les sites, qui est rattachée ici.
    """
    rows = []
    for row in payload["new_source_facts"]:
        row = dict(row)
        context = AUDIT / f"{row['Item_ID']}-context.txt"
        if context.exists():
            metadata = json.loads(row.get("Source_Metadata_JSON") or "{}")
            metadata["editorial_context"] = context.read_text(encoding="utf-8")
            row["Source_Metadata_JSON"] = json.dumps(metadata, ensure_ascii=False, sort_keys=True)
        rows.append(row)
    return rows


def _appended(existing: list[dict], added: list[dict], key: str) -> list[dict]:
    """Ajoute les lignes absentes, sans jamais dupliquer une clé déjà présente."""
    seen = {row.get(key) for row in existing}
    return existing + [row for row in added if row.get(key) not in seen]


def _restored(existing: list[dict], audited: list[dict], key: str) -> list[dict]:
    """Rétablit l'état audité d'une clé, en remplaçant la ligne vivante.

    Une reprise déjà appliquée a pu fusionner ou rediriger l'incident : pour
    rejouer l'état de départ, la ligne auditée fait foi.
    """
    by_key = {row.get(key): row for row in existing}
    for row in audited:
        by_key[row.get(key)] = row
    return list(by_key.values())


def build(destination: Path) -> Path:
    """Écrit l'état audité — 130 observations, 76 incidents — sous ``destination``."""
    payload = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    data = destination / "data"
    data.mkdir(parents=True, exist_ok=True)
    for name in _COPIED:
        origin = store.DATA_DIR / name
        if origin.exists():
            shutil.copyfile(origin, data / name)

    # Reconstituer exactement l'état audité, même après une PURGE suivie d'une
    # nouvelle collecte : les observations ciblées remplacent leurs versions
    # vivantes déjà corrigées, et une troisième observation du même événement
    # (par exemple VEILLE_LLM) ne doit pas modifier ce test de reprise à deux
    # sources.
    audited_item_ids = {row["Item_ID"] for row in payload["new_items"]}
    items = [
        row for row in store.read_csv(store.ITEMS_CSV)
        if row.get("Item_ID") in audited_item_ids
        or row.get("Organisation_Key") not in {"le tampon", "ville du tampon"}
    ]
    items = _restored(items, payload["new_items"], "Item_ID")
    incidents = store.read_csv(store.INCIDENTS_CSV)
    for row in incidents:
        row["Organisation"] = _CANONICAL_LABELS.get(row["Organisation"], row["Organisation"])
    incidents = _restored(incidents, _audited_incidents(), "Incident_ID")
    facts = _appended(store.read_csv(store.SOURCE_FACTS_CSV), _audited_facts(payload), "Item_ID")
    registry = _restored(store.read_csv(store.INCIDENT_ID_REGISTRY_CSV), [
        {"Incident_ID": SURVIVING_INCIDENT, "Anchor_Item_ID": FRENCHBREACHES_ITEM,
         "Organisation_Key": "ville du tampon", "Redirect_To": ""},
        {"Incident_ID": REDIRECTED_INCIDENT, "Anchor_Item_ID": CYBERATTAQUE_ITEM,
         "Organisation_Key": "le tampon", "Redirect_To": ""},
    ], "Incident_ID")

    _write_csv(data / "items.csv", model.ITEM_COLUMNS, items)
    _write_csv(data / "incidents.csv", model.INCIDENT_COLUMNS, incidents)
    _write_csv(data / "source_facts.csv", model.SOURCE_FACT_COLUMNS, facts)
    _write_csv(data / "incident_id_registry.csv", REGISTRY_COLUMNS, registry)
    (data / "snapshot.json").write_text(
        json.dumps(payload["snapshot"], ensure_ascii=False), encoding="utf-8"
    )
    (data / "dedup_review_queue.json").write_text(json.dumps([
        {"pair_key": f"{FRENCHBREACHES_ITEM}|{CYBERATTAQUE_ITEM}",
         "left": FRENCHBREACHES_ITEM, "right": CYBERATTAQUE_ITEM, "status": "DISABLED"},
        {"pair_key": "ITM-autre|ITM-encore", "left": "ITM-autre", "right": "ITM-encore",
         "status": "DISABLED"},
    ], ensure_ascii=False), encoding="utf-8")
    (destination / "assets" / "data").mkdir(parents=True, exist_ok=True)
    return data


def store_targets(destination: Path) -> dict[str, Path]:
    """Constantes de `store` à rediriger vers l'état reconstitué."""
    data = destination / "data"
    return {
        "DATA_DIR": data,
        "SITE_DATA_DIR": destination / "assets" / "data",
        "ITEMS_CSV": data / "items.csv",
        "INCIDENTS_CSV": data / "incidents.csv",
        "SOURCE_FACTS_CSV": data / "source_facts.csv",
        "SNAPSHOT_JSON": data / "snapshot.json",
        "INCIDENT_ID_REGISTRY_CSV": data / "incident_id_registry.csv",
        "INCIDENT_DEDUP_REGISTRY_CSV": data / "incident_dedup_registry.csv",
        "SECTOR_RESOLUTION_CSV": data / "sector_resolution.csv",
        "ENRICHMENT_REFERENCE_CSV": data / "enrichment_reference.csv",
        "ORGANISATION_IDENTITY_REGISTRY_CSV": data / "organisation_identity_registry.csv",
        "RUN_LOG_CSV": data / "run_log.csv",
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", help="Répertoire de travail à créer")
    args = parser.parse_args(argv)
    if not available():
        print("preuves d'audit absentes de l'arbre", file=sys.stderr)
        return 1
    data = build(Path(args.destination))
    print(json.dumps({
        "data_dir": str(data),
        "items": len(store.read_csv(data / "items.csv")),
        "incidents": len(store.read_csv(data / "incidents.csv")),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
