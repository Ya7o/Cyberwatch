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


def _canonical_content(item) -> dict[str, str]:
    """Contenu devant être identique pour consolider deux anciens Item_ID."""
    row = item.to_row()
    row.pop("Item_ID", None)
    row.pop("Collected_As_Of", None)
    return row


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
        if new_item_id != old_id:
            changed_item_ids += 1
        by_new_id[new_item_id].append((old_id, item))

    rebuilt_items = []
    collapsed_items = 0
    for new_item_id in sorted(by_new_id):
        members = sorted(by_new_id[new_item_id], key=lambda pair: pair[0])
        if len(members) > 1:
            reference = _canonical_content(members[0][1])
            if any(_canonical_content(item) != reference for _, item in members[1:]):
                print("REBUILD_DEDUP_ABORT non-identical Item_ID collision " + new_item_id)
                for old_id, item in members:
                    print("COLLISION_ROW " + json.dumps(
                        {"old_id": old_id, **item.to_row()},
                        sort_keys=True,
                        ensure_ascii=False,
                    ))
                return 1
            collapsed_items += len(members) - 1

        chosen = members[0][1]
        chosen.Item_ID = new_item_id
        collected = sorted(
            item.Collected_As_Of for _, item in members if item.Collected_As_Of
        )
        chosen.Collected_As_Of = collected[0] if collected else ""
        rebuilt_items.append(chosen)

    items = identity.sort_items(rebuilt_items)
    incidents = build_incidents(items)
    after_hash = identity.incidents_hash(incidents)

    store.save_items(items)
    store.save_incidents(incidents)
    store.write_json(store.SITE_DATA_DIR / "incidents.json", incidents_payload(incidents))

    audit = {
        "items_before": sum(len(rows) for rows in by_new_id.values()),
        "items_after": len(items),
        "items_collapsed_exact_duplicates": collapsed_items,
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
