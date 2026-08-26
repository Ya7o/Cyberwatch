#!/usr/bin/env python3
"""Teste la page officielle des organisations dont le nom EST un domaine.

Cible volontairement étroite (cf. `cyberwatch/domain_page_sector.py`) : les
organisations encore en Secteur Inconnu dont le nom collecté est déjà une
forme de domaine (`Klark.ai`, `iMapper.tech`). Il n'y a donc aucun site à
deviner, contrairement au balayage général mesuré le 2026-08-23
(`audit/SECTOR_QUALIFICATION_AUDIT.md`, 60 testées / 0 correspondance).

Le worker ne publie aucun secteur : il enrichit le cache
`data/organisation_domain_page.csv`, relu ensuite hors-ligne par
`organisation_sector.py` comme une preuve faible parmi d'autres. Il affiche
les statistiques du lot pour permettre de décider, sur mesure et non sur
intuition, si ce canal mérite d'être branché dans un workflow.

Convention d'exploitation : DOMAIN_PAGE_MAX_ORGS=0 signifie « toute la file ».
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import domain_page_sector as dps, store


def _max_orgs() -> int:
    try:
        return max(0, int(os.getenv("DOMAIN_PAGE_MAX_ORGS", "20")))
    except ValueError:
        return 20


def main() -> int:
    items = store.load_items()
    candidates = dps.select_organisations(items)
    limit = _max_orgs()
    batch = candidates if limit == 0 else candidates[:limit]

    print(f"File : {len(candidates)} organisation(s) Inconnu avec un nom en forme de domaine.")
    if not batch:
        print("Rien à tester.")
        return 0

    cached = {row.get("Organisation_Key", ""): row for row in dps.load_cache()}
    stats = {"tested": 0, "matched": 0, "no_evidence": 0, "unreachable": 0}

    for key, organisation in batch:
        row = dps.resolve_domain_page(organisation)
        if row is None:
            continue
        stats["tested"] += 1
        row["Organisation_Key"] = key
        cached[key] = row
        if row["Status"] == dps.STATUS_MATCHED:
            stats["matched"] += 1
        elif row["Status"] == dps.STATUS_UNREACHABLE:
            stats["unreachable"] += 1
        else:
            stats["no_evidence"] += 1
        print(
            f"  {organisation} -> {row['URL']} : {row['Status']}"
            + (f" ({row['Activity_Sector_Match']} — {row['Activity_Description']})" if row["Activity_Sector_Match"] else "")
        )

    # Les échecs sont persistés au même titre que les succès : sans cela, un
    # relancement retesterait indéfiniment les mêmes organisations (bug déjà
    # constaté sur enrich_sector_queue.py, cf. audit du 2026-08-23).
    dps.save_cache(list(cached.values()))

    print(
        f"\nSTATS testées={stats['tested']} preuve={stats['matched']} "
        f"sans_preuve={stats['no_evidence']} injoignable={stats['unreachable']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
