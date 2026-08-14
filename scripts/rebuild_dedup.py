"""Reconstruction déterministe de la base après évolution des alias.

Cette commande est volontairement locale et sans réseau : elle repart du snapshot
`data/items.csv`, recalcule les identités d'organisation, reconstruit les
incidents et régénère uniquement le JSON des incidents du dashboard.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

# Permet l'exécution directe `python scripts/rebuild_dedup.py` depuis la racine
# sans installation du package.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import identity, store
from cyberwatch.dedup import build_incidents
from cyberwatch.normalize import organisation_key
from cyberwatch.site import incidents_payload


def main() -> int:
    items = store.load_items()
    before_incidents = store.load_incidents()
    before_hash = identity.incidents_hash(before_incidents)

    changed_keys = 0
    changed_item_ids = 0
    by_new_id = defaultdict(list)

    for item in items:
        old_id = item.Item_ID
        old_key = item.Organisation_Key
        new_key = organisation_key(item.Organisation_Raw)
        if new_key != old_key:
            item.Organisation_Key = new_key
            changed_keys += 1

        new_item_id = identity.item_id(
            item.Source_ID,
            item.Published_Date,
            item.Organisation_Key,
            item.URL,
            item.Source_Item_ID,
        )
        by_new_id[new_item_id].append(
            {
                "old_id": old_id,
                "source": item.Source_ID,
                "source_item_id": item.Source_Item_ID,
                "date": item.Published_Date,
                "raw": item.Organisation_Raw,
                "old_key": old_key,
                "new_key": item.Organisation_Key,
                "url": item.URL,
            }
        )
        if new_item_id != old_id:
            item.Item_ID = new_item_id
            changed_item_ids += 1

    collisions = {
        item_id: rows for item_id, rows in by_new_id.items() if len(rows) > 1
    }
    if collisions:
        print("REBUILD_DEDUP_ABORT collisions after canonicalisation")
        for item_id in sorted(collisions):
            print("COLLISION " + item_id + " " + json.dumps(
                collisions[item_id], sort_keys=True, ensure_ascii=False
            ))
        return 1

    items = identity.sort_items(items)
    incidents = build_incidents(items)
    after_hash = identity.incidents_hash(incidents)

    store.save_items(items)
    store.save_incidents(incidents)
    store.write_json(store.SITE_DATA_DIR / "incidents.json", incidents_payload(incidents))

    audit = {
        "items": len(items),
        "incidents_before": len(before_incidents),
        "incidents_after": len(incidents),
        "incident_delta": len(incidents) - len(before_incidents),
        "organisation_keys_changed": changed_keys,
        "item_ids_changed": changed_item_ids,
        "incidents_hash_before": before_hash,
        "incidents_hash_after": after_hash,
    }
    print("REBUILD_DEDUP_AUDIT " + json.dumps(audit, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
