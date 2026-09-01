"""CLI minimale du prototype Cyberwatch."""

from __future__ import annotations

import argparse
import sys

from . import config, site, status, store
from .runner import MODE_CREATE, MODE_MAJ, execute, make_run_context


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


def _run(mode: str, args) -> int:
    if mode == MODE_MAJ and store.snapshot_state()[0] != store.BASE_VALID:
        print("ERREUR : Aucun snapshot Cyberwatch valide n'existe. Lancez create.")
        return 1

    context = make_run_context(
        mode,
        getattr(args, "as_of", None),
        getattr(args, "start", None) if mode == MODE_CREATE else None,
        _layers(getattr(args, "layers", "all")),
    )
    transient = bool(getattr(args, "transient", False))
    report = execute(context, persist=False) if transient else execute(context)
    _print_summary(report)
    if report.overall != status.BROKEN and not transient:
        site.build()
    return 1 if report.overall == status.BROKEN else 0


def cmd_create(args) -> int:
    return _run(MODE_CREATE, args)


def cmd_maj(args) -> int:
    return _run(MODE_MAJ, args)


def cmd_build_site(_args) -> int:
    incidents, sources = site.build()
    print(f"Dashboard généré : {incidents} incidents, {sources} sources.")
    return 0


def cmd_report(_args) -> int:
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
    item_ids = [row.Item_ID for row in items]
    incident_ids = [row.Incident_ID for row in incidents]
    if len(item_ids) != len(set(item_ids)) or len(incident_ids) != len(set(incident_ids)):
        print("BASE INCOHÉRENTE : identifiant dupliqué")
        return 1
    print(f"OK — {len(items)} items, {len(incidents)} incidents")
    return 0


def _common(parser: argparse.ArgumentParser, *, allow_start: bool) -> None:
    parser.add_argument("--as-of", dest="as_of")
    if allow_start:
        parser.add_argument("--start")
    parser.add_argument("--layers", default="all")
    parser.add_argument("--transient", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cyberwatch", description="Veille cyber quotidienne.")
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create", help="Reconstruire depuis le 28 août.")
    _common(create, allow_start=True)
    create.set_defaults(func=cmd_create)

    maj = commands.add_parser("maj", help="Collecter aujourd'hui et hier.")
    _common(maj, allow_start=False)
    maj.set_defaults(func=cmd_maj)

    build = commands.add_parser("build-site", help="Régénérer le dashboard.")
    build.set_defaults(func=cmd_build_site)

    report = commands.add_parser("report", help="Afficher le dernier run.")
    report.set_defaults(func=cmd_report)

    check = commands.add_parser("check", help="Vérifier que les fichiers sont lisibles.")
    check.add_argument("--allow-uninitialized", action="store_true")
    check.set_defaults(func=cmd_check)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
