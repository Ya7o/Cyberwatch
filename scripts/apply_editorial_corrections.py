"""Applique le registre de corrections éditoriales puis reconstruit le site.

Deux modes, un seul chemin de finalisation :

* sans ``--items``, le comportement historique — tout le registre est appliqué,
  le snapshot est recalculé et, avec ``--write``, écrit ;
* avec ``--items``, une **reprise ciblée** : seules les observations nommées, leurs
  faits et leurs incidents peuvent changer. Toute autre observation ou tout autre
  incident qui bougerait sémantiquement fait échouer l'écriture.

La simulation est le défaut dans les deux cas : ``--write`` est explicite. La
reprise ciblée n'utilise pas ``repair_qualifications.py``, qui interdit tout
changement d'identifiant d'incident : une fusion en demande précisément un.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cyberwatch import enrichment, identity, site, source_facts, store  # noqa: E402

#: Journal de la réparation, distinct des journaux du run historique : ceux-ci
#: décrivent une collecte, celui-ci décrit une intervention sur son résultat.
REPAIR_REPORT_PATH = store.DATA_DIR / "editorial_repair_report.json"

DEDUP_REVIEW_QUEUE_PATH = store.DATA_DIR / "dedup_review_queue.json"


def _item_rows(items) -> dict[str, dict]:
    return {item.Item_ID: item.to_row() for item in items}


def _incident_rows(incidents) -> dict[str, dict]:
    return {incident.Incident_ID: incident.to_row() for incident in incidents}


def _fact_rows(rows: list[dict]) -> dict[str, dict]:
    return {str(row.get("Item_ID") or ""): dict(row) for row in rows}


def _diff(before: dict[str, dict], after: dict[str, dict]) -> dict[str, dict]:
    """Différences champ par champ, par identifiant, dans les deux sens."""
    out: dict[str, dict] = {}
    for key in sorted(set(before) | set(after)):
        old, new = before.get(key), after.get(key)
        if old == new:
            continue
        if old is None:
            out[key] = {"added": new}
        elif new is None:
            out[key] = {"removed": old}
        else:
            out[key] = {
                field: {"before": old.get(field, ""), "after": new.get(field, "")}
                for field in sorted(set(old) | set(new))
                if old.get(field, "") != new.get(field, "")
            }
    return out


def _scoped_incidents(incidents, scope: set[str], items_by_incident: dict[str, set[str]]) -> set[str]:
    """Incidents dont au moins une observation appartient au périmètre."""
    return {
        incident.Incident_ID
        for incident in incidents
        if items_by_incident.get(incident.Incident_ID, set()) & scope
    }


def _items_by_incident(items, incidents) -> dict[str, set[str]]:
    """Rattache chaque observation à son incident par ses URL de sources."""
    item_by_url = {item.URL: item.Item_ID for item in items if item.URL}
    out: dict[str, set[str]] = {}
    for incident in incidents:
        members = {
            item_by_url[url.strip()]
            for url in str(incident.Source_URLs or "").split(" | ")
            if url.strip() in item_by_url
        }
        out[incident.Incident_ID] = members
    return out


def _redirects(registry: list[dict]) -> dict[str, str]:
    return {
        str(row.get("Incident_ID") or ""): str(row.get("Redirect_To") or "")
        for row in registry
        if str(row.get("Redirect_To") or "")
    }


def _reconcile_dedup_queue(merged_items: set[str]) -> list[str]:
    """Retire de la file de revue les paires que la fusion vient de résoudre.

    Les demandes réellement non résolues sont conservées : une reprise ciblée
    ne vide pas la file, elle en retire seulement ce qu'elle a traité.
    """
    try:
        rows = json.loads(DEDUP_REVIEW_QUEUE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return []
    if not isinstance(rows, list):
        return []
    resolved = [
        row for row in rows
        if isinstance(row, dict)
        and {str(row.get("left") or ""), str(row.get("right") or "")} <= merged_items
    ]
    if not resolved:
        return []
    kept = [row for row in rows if row not in resolved]
    store.write_json(DEDUP_REVIEW_QUEUE_PATH, kept)
    return [str(row.get("pair_key") or "") for row in resolved]


def _parse_scope(values: list[str] | None) -> set[str]:
    scope: set[str] = set()
    for value in values or ():
        scope.update(token.strip() for token in value.split(",") if token.strip())
    return scope


def _guard(summary: dict, scope: set[str], out_of_scope: dict) -> list[str]:
    problems: list[str] = []
    if out_of_scope["items"]:
        problems.append(
            "observations hors périmètre modifiées : "
            + ", ".join(sorted(out_of_scope["items"]))
        )
    if out_of_scope["incidents"]:
        problems.append(
            "incidents hors périmètre modifiés : "
            + ", ".join(sorted(out_of_scope["incidents"]))
        )
    missing = sorted(scope - set(summary["known_items"]))
    if missing:
        problems.append("observations absentes du snapshot : " + ", ".join(missing))
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true",
                        help="Écrit le snapshot et le site après validation")
    parser.add_argument("--items", action="append", default=[],
                        help="Périmètre explicite d'Item_ID (répétable ou séparé par des virgules)")
    parser.add_argument("--report", default="",
                        help="Chemin du rapport détaillé ; par défaut data/editorial_repair_report.json")
    args = parser.parse_args(argv)
    scope = _parse_scope(args.items)

    # --- état de départ -----------------------------------------------------
    items_before = store.load_items()
    incidents_before = store.load_incidents()
    facts_before = store.load_source_facts()
    registry_before = store.load_incident_id_registry()
    snapshot = store.load_snapshot()

    before = {
        "items": _item_rows(items_before),
        "incidents": _incident_rows(incidents_before),
        "facts": _fact_rows(facts_before),
        "redirects": _redirects(registry_before),
    }

    # --- application des corrections ciblées --------------------------------
    facts, corrected_facts = source_facts.sanitize_source_facts(copy.deepcopy(facts_before))
    report = enrichment.finalize_snapshot(
        copy.deepcopy(items_before),
        facts,
        run_id=str(snapshot.get("Run_ID") or "EDITORIAL-CORRECTION"),
        as_of=str(snapshot.get("As_Of") or snapshot.get("as_of")
                  or dt.datetime.now(dt.UTC).isoformat()),
    )

    after = {
        "items": _item_rows(report.items),
        "incidents": _incident_rows(report.incidents),
        "facts": _fact_rows(facts),
        "redirects": _redirects(report.incident_id_registry),
    }

    changes = {section: _diff(before[section], after[section])
               for section in ("items", "incidents", "facts")}
    new_redirects = {
        incident: target for incident, target in after["redirects"].items()
        if before["redirects"].get(incident) != target
    }

    summary = {
        "scope": sorted(scope),
        "known_items": sorted(before["items"]),
        "corrected_source_facts": corrected_facts,
        "items_before": len(items_before),
        "items_after": len(report.items),
        "incidents_before": len(incidents_before),
        "incidents_after": len(report.incidents),
        "changed_items": sorted(changes["items"]),
        "changed_incidents": sorted(changes["incidents"]),
        "changed_source_facts": sorted(changes["facts"]),
        "new_redirects": new_redirects,
        "changes": changes,
    }

    problems: list[str] = []
    if scope:
        members = _items_by_incident(items_before, incidents_before)
        scoped_incidents = _scoped_incidents(incidents_before, scope, members)
        # Un incident qui disparaît en redirigeant vers un incident du périmètre
        # est le résultat attendu d'une fusion, pas une dérive hors périmètre.
        allowed_incidents = scoped_incidents | set(new_redirects) | set(new_redirects.values())
        out_of_scope = {
            "items": set(changes["items"]) - scope,
            "incidents": set(changes["incidents"]) - allowed_incidents,
        }
        problems = _guard(summary, scope, out_of_scope)
        summary["out_of_scope"] = {key: sorted(value) for key, value in out_of_scope.items()}

    summary["problems"] = problems
    summary["written"] = False

    if problems:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        print("ÉCRITURE REFUSÉE : " + " ; ".join(problems), file=sys.stderr)
        return 1

    if args.write:
        store.save_source_facts(facts)
        store.save_items(report.items)
        store.save_incidents(report.incidents)
        store.save_incident_id_registry(report.incident_id_registry)
        store.save_sector_resolution(report.sector_resolution_rows)
        snapshot.update(
            Items_Count=len(report.items),
            Incidents_Count=len(report.incidents),
            Items_Hash=identity.items_hash(report.items),
            Incidents_Hash=identity.incidents_hash(report.incidents),
        )
        store.save_snapshot(snapshot)
        merged_items = {
            item_id for incident in new_redirects
            for item_id in _items_by_incident(items_before, incidents_before).get(incident, set())
        } | scope
        summary["dedup_pairs_reconciled"] = _reconcile_dedup_queue(merged_items)
        site.build()
        summary["written"] = True

    path = Path(args.report) if args.report else REPAIR_REPORT_PATH
    store.write_json(path, {
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "run_id": str(snapshot.get("Run_ID") or ""),
        **{key: value for key, value in summary.items() if key != "known_items"},
    })
    printable = {key: value for key, value in summary.items()
                 if key not in {"changes", "known_items"}}
    print(json.dumps(printable, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
