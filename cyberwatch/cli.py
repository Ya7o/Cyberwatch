"""CLI minimale du prototype Cyberwatch."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import config, enrichment, production, qualification, reset, sector_resolution, site, status, store
from .runner import MODE_MAJ, execute, make_run_context


def _layers(value: str) -> list[str]:
    selected: list[str] = []
    for token in (value or "all").split(","):
        selected.extend(config.LAYER_GROUPS.get(token.strip().lower(), []))
    return selected or config.LAYER_GROUPS["all"]


def _summary(report) -> None:
    counts = status.status_counts(report.outcomes)
    print(
        f"{report.context.mode} {report.context.target_start} -> {report.context.target_end} | "
        f"{len(report.items)} items | {len(report.incidents)} incidents | "
        f"+{report.new_incidents} nouveaux | "
        f"{counts.get(status.OK, 0)} sources OK | {report.overall}"
    )
    for problem in report.problems:
        print(f"! {problem}")


# Compatibilité des quelques tests et appels internes existants.
_print_summary = _summary


def _run(args) -> int:
    if store.snapshot_state()[0] == store.BASE_INCOHERENT:
        print("ERREUR : Base incohérente. Corriger les données ou lancer PURGE pour repartir de zéro.")
        return 1

    context = make_run_context(
        MODE_MAJ,
        getattr(args, "as_of", None),
        _layers(getattr(args, "layers", "all")),
    )
    transient = bool(getattr(args, "transient", False))
    report = execute(context, persist=False) if transient else execute(context)
    _print_summary(report)
    if report.overall != status.BROKEN and not transient:
        site.build()
    return 1 if report.overall == status.BROKEN else 0


def cmd_maj(args) -> int:
    return _run(args)


def cmd_purge(_args) -> int:
    try:
        reset.purge()
    except (OSError, ValueError) as exc:
        print(f"ERREUR : PURGE interrompue : {exc}", file=sys.stderr)
        return 1
    site.build()
    print("PURGE terminée : 0 item, 0 incident. La prochaine MAJ collectera hier et aujourd'hui.")
    return 0


def cmd_build_site(_args) -> int:
    incidents, sources = site.build()
    print(f"Dashboard généré : {incidents} incidents, {sources} sources.")
    return 0


def cmd_report(args) -> int:
    """Dernier run, ou rapport de qualification si `--qualification` est passé.

    Le comportement par défaut est inchangé : sans option, la commande rend
    exactement le résumé historique du dernier run.
    """
    if getattr(args, "qualification", False):
        run = qualification.load_run(getattr(args, "run_id", "") or "")
        if not run.run_id:
            print("Aucun run enregistré.")
            return 0
        print(qualification.markdown_report(run))
        return 0
    rows = store.load_run_log()
    if not rows:
        print("Aucun run enregistré.")
        return 0
    row = rows[-1]
    print(f"## {row.get('Overall_Status', '')} — {row.get('Mode', '')} `{row.get('Run_ID', '')}`")
    print(f"- Fenêtre : `{row.get('Target_Start', '')}` → `{row.get('Target_End', '')}`")
    print(f"- Items : **{row.get('Items_Count', 0)}** (+{row.get('New_Items', 0)} nouveaux)")
    print(f"- Incidents : **{row.get('Incidents_Count', 0)}** (+{row.get('New_Incidents', 0)} nouveaux)")
    print(f"- Sources : **{row.get('Sources_OK', 0)} OK / {row.get('Sources_FAIL', 0)} FAIL**")
    print(f"- Coût LLM : **${float(row.get('LLM_Cost_USD') or 0):.6f}** ({row.get('LLM_Calls', 0)} appels)")
    return 0


def cmd_validate_business(_args) -> int:
    business = production.evaluate_business_corpus()
    dedup = production.evaluate_dedup_corpus()
    print(json.dumps({"business": business, "dedup": dedup}, ensure_ascii=False, indent=2))
    return 0 if business["passed"] and dedup["known_nonduplicate_false_merge_count"] == 0 else 1


def cmd_production_status(args) -> int:
    payload = production.health_payload()
    rendered = production.markdown_report(payload) if args.markdown else json.dumps(
        payload, ensure_ascii=False, indent=2, sort_keys=True
    )
    print(rendered)
    if args.github_output:
        output_path = os.getenv("GITHUB_OUTPUT", "")
        if not output_path:
            print("ERREUR : GITHUB_OUTPUT est absent.", file=sys.stderr)
            return 2
        with Path(output_path).open("a", encoding="utf-8") as handle:
            handle.write(f"alert={'true' if payload['alert'] else 'false'}\n")
            handle.write("alert_reasons<<CYBERWATCH_EOF\n")
            handle.write(" ; ".join(payload["alert_reasons"]) + "\n")
            handle.write("CYBERWATCH_EOF\n")
    return 0


def cmd_check(args) -> int:
    state, problems = store.snapshot_state()
    if state == store.BASE_UNINITIALIZED:
        print("BASE NON INITIALISÉE")
        return 0 if getattr(args, "allow_uninitialized", False) else 1
    if state == store.BASE_INCOHERENT:
        print("BASE INCOHÉRENTE")
        for problem in problems:
            print(f"! {problem}")
        return 1

    items = store.load_items()
    incidents = store.load_incidents()
    gaps = sector_resolution.fact_transport_gaps(items, store.load_source_facts(), enrichment.load_reference())
    gaps.extend(sector_resolution.transport_gaps(items, store.load_sector_resolution()))
    if gaps:
        print("BASE INCOHÉRENTE : preuves sectorielles non transmises : " + ", ".join(sorted(set(gaps))))
        return 1
    item_ids = [row.Item_ID for row in items]
    incident_ids = [row.Incident_ID for row in incidents]
    if len(item_ids) != len(set(item_ids)) or len(incident_ids) != len(set(incident_ids)):
        print("BASE INCOHÉRENTE : identifiant dupliqué")
        return 1
    print(f"OK — {len(items)} items, {len(incidents)} incidents")
    return 0


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--as-of", dest="as_of")
    parser.add_argument("--layers", default="all")
    parser.add_argument("--transient", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cyberwatch", description="Veille cyber quotidienne.")
    commands = parser.add_subparsers(dest="command", required=True)

    maj = commands.add_parser("maj", aliases=["MAJ"], help="Collecter aujourd'hui et hier.")
    _common(maj)
    maj.set_defaults(func=cmd_maj)

    purge = commands.add_parser("purge", aliases=["PURGE"], help="Vider la base et le dashboard, sans collecte.")
    purge.set_defaults(func=cmd_purge)

    build = commands.add_parser("build-site", help="Régénérer le dashboard.")
    build.set_defaults(func=cmd_build_site)

    report = commands.add_parser("report", help="Afficher le dernier run.")
    report.add_argument(
        "--qualification", action="store_true",
        help="Rendre les tableaux extraction/décision et déduplication du run.",
    )
    report.add_argument(
        "--run-id", dest="run_id", default="",
        help="Run à rapporter ; par défaut le dernier run journalisé.",
    )
    report.set_defaults(func=cmd_report)

    validate_business = commands.add_parser(
        "validate-business", help="Exécuter le corpus de validation métier."
    )
    validate_business.set_defaults(func=cmd_validate_business)

    production_status = commands.add_parser(
        "production-status", help="Afficher fraîcheur, fiabilité, qualité et coût."
    )
    production_status.add_argument("--markdown", action="store_true")
    production_status.add_argument("--github-output", action="store_true")
    production_status.set_defaults(func=cmd_production_status)

    check = commands.add_parser("check", help="Vérifier que les fichiers sont lisibles.")
    check.add_argument("--allow-uninitialized", action="store_true")
    check.set_defaults(func=cmd_check)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
