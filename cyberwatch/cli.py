"""Interface en ligne de commande.

Commandes disponibles :

    create        construit la base depuis zéro (§24)
    maj           met à jour sur la fenêtre glissante de 14 jours (§25)
    replay        reconstruit INCIDENTS depuis ITEMS, sans accès Web (§26)
    test-repeat   test de répétabilité (§27)
    diagnose      sonde les sources et mesure le coût réel, sans écrire la base
    build-site    régénère les données du dashboard
    check         rejoue les contrôles avant export (§29)
"""

from __future__ import annotations

import argparse
import random
import sys

from . import config, identity, site, sources, status, store
from .collectors.base import Window
from .dedup import build_incidents
from .http import Budget, HttpClient
from .runner import (
    MODE_CREATE,
    MODE_DIAGNOSE,
    MODE_MAJ,
    MODE_REPLAY,
    execute,
    make_run_context,
    pre_export_checks,
)


def _layers_from(value: str) -> list[str]:
    """Traduit `--layers core,local_media` en liste de couches."""
    layers: list[str] = []
    for token in (value or "all").split(","):
        token = token.strip().lower()
        layers.extend(config.LAYER_GROUPS.get(token, []))
    return layers or config.LAYER_GROUPS["all"]


def _print_summary(report) -> None:
    """Synthèse de fin de run, avec la lecture explicite du statut global."""
    counts = status.status_counts(report.outcomes)
    print()
    print("=" * 74)
    print(f"  Run           : {report.context.run_id}  ({report.context.mode})")
    print(f"  Fenêtre       : {report.context.target_start} -> {report.context.target_end}")
    print(f"  Items         : {len(report.items):5}  (+{report.new_items} nouveaux)")
    print(f"  Incidents     : {len(report.incidents):5}  (+{report.new_incidents} nouveaux)")
    print(
        f"  Sources       : {counts.get(status.OK, 0)} OK · "
        f"{counts.get(status.PARTIAL, 0)} PARTIAL · "
        f"{counts.get(status.FAIL, 0)} FAIL · "
        f"{counts.get(status.SKIPPED, 0)} hors périmètre"
    )
    print(f"  Health score  : {report.health}/100")
    print(f"  Statut global : {report.overall} — {status.RUN_STATUS_LABELS[report.overall]}")
    print(f"  Items_Hash    : {report.items_hash[:32]}")
    print(f"  Incidents_Hash: {report.incidents_hash[:32]}")
    print(f"  Durée         : {report.duration}s · {report.requests} requêtes")

    spots = status.blind_spots(report.outcomes)
    if spots:
        print()
        print("  Angles morts de ce run :")
        for spot in spots:
            detail = f" ({spot['detail']})" if spot["detail"] else ""
            print(
                f"    - {spot['source_id']:28} {spot['status']:8} "
                f"{spot['coverage']:3}%{detail} — {spot['reason']}"
            )

    if report.problems:
        print()
        print("  Contrôles avant export (§29) :")
        for problem in report.problems:
            print(f"    ! {problem}")
    print("=" * 74)


def cmd_create(args) -> int:
    context = make_run_context(
        MODE_CREATE, args.as_of, args.start, _layers_from(args.layers)
    )
    print(f"CREATE {context.run_id} — fenêtre {context.target_start} -> {context.target_end}")
    report = execute(context)
    _print_summary(report)
    site.build()
    return 0 if report.overall != status.BROKEN else 1


def cmd_maj(args) -> int:
    context = make_run_context(
        MODE_MAJ, args.as_of, args.start, _layers_from(args.layers)
    )
    print(f"MAJ {context.run_id} — fenêtre {context.target_start} -> {context.target_end}")
    report = execute(context)
    _print_summary(report)
    site.build()
    return 0 if report.overall != status.BROKEN else 1


def cmd_replay(args) -> int:
    """Reconstruit INCIDENTS depuis ITEMS, sans aucun accès Web (§26)."""
    context = make_run_context(MODE_REPLAY, args.as_of, args.start)
    before = store.load_incidents()
    before_hash = identity.incidents_hash(before)

    report = execute(context, offline=True)
    print(f"REPLAY {context.run_id}")
    print(f"  Items       : {len(report.items)}")
    print(f"  Incidents   : {len(report.incidents)} (avant : {len(before)})")
    print(f"  Hash avant  : {before_hash[:32]}")
    print(f"  Hash après  : {report.incidents_hash[:32]}")

    if before and before_hash != report.incidents_hash:
        print("  ATTENTION : la reconstruction ne redonne pas le hash précédent.")
        print("  Cela signifie que la version de méthode a changé le résultat.")
    else:
        print("  Reconstruction identique : transformation ITEMS -> INCIDENTS stable.")
    site.build()
    return 0


def cmd_test_repeat(args) -> int:
    """Test de répétabilité du §27 : deux constructions, quatre égalités."""
    items = store.load_items()
    if not items:
        # Base neuve : il n'y a rien à comparer, ce n'est pas un échec.
        # La répétabilité du moteur reste couverte par tests/test_identity.py,
        # qui s'exécute sur des jeux de données figés.
        print("TEST REPETABILITE (§27)")
        print("  Base vide : aucun ITEMS à rejouer, test sans objet.")
        print("  Le moteur reste couvert par les tests unitaires sur fixtures.")
        return 0

    build_a = build_incidents(items)
    hash_items_a = identity.items_hash(items)
    hash_incidents_a = identity.incidents_hash(build_a)

    shuffled = list(items)
    random.Random(20260812).shuffle(shuffled)
    build_b = build_incidents(shuffled)
    hash_items_b = identity.items_hash(shuffled)
    hash_incidents_b = identity.incidents_hash(build_b)

    checks = [
        ("Nombre d'items", len(items), len(shuffled)),
        ("Items_Hash", hash_items_a, hash_items_b),
        ("Nombre d'incidents", len(build_a), len(build_b)),
        ("Incidents_Hash", hash_incidents_a, hash_incidents_b),
    ]

    print("TEST REPETABILITE (§27)")
    print(f"  Ordre d'entrée A : ordre canonique ({len(items)} items)")
    print(f"  Ordre d'entrée B : ordre aléatoire figé")
    print()
    passed = True
    for label, left, right in checks:
        ok = left == right
        passed = passed and ok
        shown = str(left)[:32]
        print(f"  {'PASS' if ok else 'FAIL'}  {label:22} {shown}")

    print()
    print("  RESULTAT :", "PASS" if passed else "FAIL")
    return 0 if passed else 1


def cmd_diagnose(args) -> int:
    """Sonde chaque source et mesure son coût réel, sans écrire la base.

    C'est le mode à lancer en premier sur un environnement neuf : il indique
    par quel chemin chaque source est réellement lisible, et ce que coûterait
    un run complet.
    """
    from .runner import make_run_context, run_source
    from . import watchlists

    context = make_run_context(
        MODE_DIAGNOSE, args.as_of, args.start, _layers_from(args.layers)
    )
    window = context.window
    print(f"DIAGNOSE — fenêtre {window.start} -> {window.end}")
    print(f"Budget du run : {config.MAX_REQUESTS_PER_RUN} requêtes / "
          f"{config.MAX_SECONDS_PER_RUN // 60} min")
    print()

    estimated = sum(
        sources.expected_units(spec) for spec in sources.active_sources(context.layers)
    )
    print(f"Unités attendues pour ce périmètre : {estimated}")
    print()

    client = HttpClient(
        run_budget=Budget(config.MAX_REQUESTS_PER_RUN, config.MAX_SECONDS_PER_RUN)
    )
    known_orgs = watchlists.known_organisations()
    entity_index = watchlists.entity_index()

    header = (
        f"{'Source':28} {'Statut':8} {'Cov':>4} {'Items':>6} {'Req':>5} "
        f"{'Durée':>7}  Accès / raison"
    )
    print(header)
    print("-" * len(header))

    total_calls = 0
    for spec in sources.active_sources(context.layers):
        if args.only and spec.source_id != args.only:
            continue
        outcome, items, _rows = run_source(
            client, spec, context, known_orgs, entity_index
        )
        total_calls += outcome.calls
        detail = outcome.access_method or outcome.reason_code
        if outcome.comment:
            detail = f"{detail} — {outcome.comment[:60]}"
        print(
            f"{outcome.source_id:28} {outcome.status:8} {outcome.coverage:3}% "
            f"{outcome.items_collected:6} {outcome.calls:5} "
            f"{outcome.duration_seconds:6}s  {detail}"
        )

    print()
    print(f"Total requêtes réelles : {total_calls}")
    print(f"Durée totale           : {round(client.run_budget.elapsed, 1)}s")
    print("Aucune donnée n'a été écrite (mode diagnostic).")
    return 0


def cmd_report(args) -> int:
    """Résumé Markdown du dernier run, pour le récapitulatif GitHub Actions."""
    run_log = store.load_run_log()
    if not run_log:
        print("Aucun run enregistré.")
        return 0

    last = run_log[-1]
    run_id = last.get("Run_ID", "")
    rows = [r for r in store.load_run_sources() if r.get("Run_ID") == run_id]

    overall = last.get("Overall_Status", "")
    icon = {"HEALTHY": "🟢", "DEGRADED": "🟡", "BROKEN": "🔴"}.get(overall, "⚪")

    print(f"## {icon} {overall} — {last.get('Mode', '')} `{run_id}`")
    print()
    print(f"- Fenêtre : `{last.get('Target_Start')}` → `{last.get('Target_End')}`")
    print(f"- Couches : `{last.get('Layers', '')}`")
    print(f"- Items : **{last.get('Items_Count')}** (+{last.get('New_Items')} nouveaux)")
    print(f"- Incidents : **{last.get('Incidents_Count')}** "
          f"(+{last.get('New_Incidents')} nouveaux)")
    print(f"- Score de couverture : **{last.get('Health_Score')}/100**")
    print(f"- Coût réel : {last.get('Requests')} requêtes en {last.get('Duration_s')}s")
    print()
    print("| Source | Couche | Statut | Couv. | Items | Accès | Raison |")
    print("|---|---|---|---:|---:|---|---|")

    def severity(row):
        return (
            -status.STATUS_SEVERITY.get(row.get("Status", ""), 0),
            row.get("Source_ID", ""),
        )

    for row in sorted(rows, key=severity):
        print(
            f"| `{row.get('Source_ID')}` | {row.get('Layer')} | {row.get('Status')} "
            f"| {row.get('Coverage')}% | {row.get('Items_collected')} "
            f"| {row.get('Access_Method') or '—'} "
            f"| {row.get('Reason', '').replace('|', '/')} |"
        )

    notes = last.get("Notes", "")
    if notes:
        print()
        print(f"> Contrôles avant export : {notes}")
    return 0


def cmd_build_site(args) -> int:
    incidents, sources_count = site.build()
    print(f"Données du dashboard régénérées : {incidents} incidents, "
          f"{sources_count} sources.")
    return 0


def cmd_check(args) -> int:
    items = store.load_items()
    incidents = store.load_incidents()
    problems = pre_export_checks(items, incidents, [])
    # Les contrôles portant sur RUN_SOURCES ne s'appliquent pas hors run.
    problems = [p for p in problems if "RUN_SOURCES" not in p]

    print(f"Contrôles avant export (§29) — {len(items)} items, {len(incidents)} incidents")
    if not problems:
        print("  Tous les contrôles passent.")
        return 0
    for problem in problems:
        print(f"  ! {problem}")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberwatch",
        description="Observatoire des incidents cyber France / Océan Indien.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common(sub, with_layers=True):
        sub.add_argument("--as-of", dest="as_of", help="Cutoff figé, format ISO 8601.")
        sub.add_argument("--start", help="Début de fenêtre, format AAAA-MM-JJ.")
        if with_layers:
            sub.add_argument(
                "--layers",
                default="all",
                help="Couches à exécuter : core, local_media, watch, all "
                     "(séparées par des virgules).",
            )

    create = subparsers.add_parser("create", help="Construire la base depuis zéro.")
    add_common(create)
    create.set_defaults(func=cmd_create)

    maj = subparsers.add_parser("maj", help="Mettre à jour la base.")
    add_common(maj)
    maj.set_defaults(func=cmd_maj)

    replay = subparsers.add_parser("replay", help="Reconstruire INCIDENTS sans réseau.")
    add_common(replay, with_layers=False)
    replay.set_defaults(func=cmd_replay)

    repeat = subparsers.add_parser("test-repeat", help="Test de répétabilité (§27).")
    repeat.set_defaults(func=cmd_test_repeat)

    diagnose = subparsers.add_parser(
        "diagnose", help="Sonder les sources et mesurer le coût réel."
    )
    add_common(diagnose)
    diagnose.add_argument("--only", help="Ne sonder qu'une seule source.")
    diagnose.set_defaults(func=cmd_diagnose)

    build = subparsers.add_parser("build-site", help="Régénérer les données du site.")
    build.set_defaults(func=cmd_build_site)

    report = subparsers.add_parser("report", help="Résumé Markdown du dernier run.")
    report.set_defaults(func=cmd_report)

    check = subparsers.add_parser("check", help="Rejouer les contrôles du §29.")
    check.set_defaults(func=cmd_check)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
