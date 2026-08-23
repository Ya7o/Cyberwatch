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

from . import config, enrichment, identity, incident_identity, organisation_sector_llm, site, sources, status, store
from .collectors.base import Window
from .collectors.cyberattaque_org import repair_existing_identities
from .dedup import build_incidents, build_incidents_with_registry
from .duplicate_audit import find_duplicate_candidates
from .http import Budget, HttpClient
from .runner import (
    MODE_CREATE,
    MODE_DIAGNOSE,
    MODE_MAJ,
    MODE_REPLAY,
    execute,
    code_commit,
    make_run_context,
    pre_export_checks,
    repair_item_integrity,
    save_snapshot_provenance,
)
from .normalize import organisation_key
from .qualification import qualify


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
    labels = {**status.RUN_STATUS_LABELS, status.OK: "Toutes les sources actives sont reconnues"}
    print(f"  Statut global : {report.overall} — {labels.get(report.overall, report.overall)}")
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
    transient = getattr(args, "transient", False)
    report = execute(context, persist=False) if transient else execute(context)
    _print_summary(report)
    if report.overall != status.BROKEN and not transient:
        site.build()
    return 0 if report.overall != status.BROKEN else 1


def cmd_maj(args) -> int:
    base_state, details = store.snapshot_state()
    if base_state != store.BASE_VALID:
        print("ERREUR : Aucun snapshot Cyberwatch valide n'existe.")
        print("Exécuter d'abord :")
        print("\n  python -m cyberwatch create")
        if base_state == store.BASE_INCOHERENT:
            print("\nBASE INCOHÉRENTE / INITIALISATION INCOMPLÈTE :")
            for detail in details:
                print(f"  ! {detail}")
        return 1
    try:
        context = make_run_context(
            MODE_MAJ, args.as_of, args.start, _layers_from(args.layers)
        )
    except ValueError as error:
        print(f"ERREUR : {error}")
        return 1
    print(f"MAJ {context.run_id} — fenêtre {context.target_start} -> {context.target_end}")
    transient = getattr(args, "transient", False)
    report = execute(context, persist=False) if transient else execute(context)
    _print_summary(report)
    if report.overall != status.BROKEN and not transient:
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


def cmd_repair_identities(args) -> int:
    """Applique les corrections déterministes du parseur aux items existants."""
    items, changed = repair_existing_identities(store.load_items())
    ids = [item.Item_ID for item in items]
    if len(ids) != len(set(ids)):
        print("Réparation annulée : collision d'Item_ID détectée.")
        return 1
    incidents, registry = build_incidents_with_registry(items, store.load_incident_id_registry())
    store.save_items(identity.sort_items(items))
    store.save_incidents(incidents)
    store.save_incident_id_registry(registry)
    save_snapshot_provenance(
        store.load_items(), store.load_incidents(), operation="REPAIR_IDENTITIES",
    )
    site.build()
    print(f"Réparation des identités : {changed} item(s) corrigé(s), {len(incidents)} incidents reconstruits.")
    return 0


def cmd_repair_integrity(args) -> int:
    """Migration locale déterministe des identités et clés naturelles."""
    items, report = repair_item_integrity(store.load_items())
    incidents, registry = build_incidents_with_registry(items, store.load_incident_id_registry())
    problems = pre_export_checks(items, incidents, [])
    problems.extend(incident_identity.validate_registry(registry, items, incidents))
    problems = [p for p in problems if "RUN_SOURCES" not in p]
    if problems:
        print("Réparation annulée :")
        for problem in problems:
            print(f"  ! {problem}")
        return 1
    store.save_items(items)
    store.save_incidents(incidents)
    store.save_incident_id_registry(registry)
    save_snapshot_provenance(
        store.load_items(), store.load_incidents(), operation="REPAIR_INTEGRITY",
    )
    site.build()
    print(
        "Réparation d'intégrité : "
        f"{report['ids_repaired']} ID(s) recalculé(s), "
        f"{report['duplicates_removed']} doublon(s) exact(s) retiré(s), "
        f"{len(items)} items, {len(incidents)} incidents."
    )
    return 0


def cmd_backfill_unknowns(args) -> int:
    """Réapplique les règles aux seules menaces/localisations inconnues."""
    items = store.load_items()
    before_ids = [item.Item_ID for item in items]
    qualified = qualify(items)
    if before_ids != [item.Item_ID for item in items]:
        print("Backfill annulé : un Item_ID aurait été modifié.")
        return 1
    items, incidents = qualified.items, qualified.incidents
    store.save_items(items)
    store.save_incidents(incidents)
    store.save_qualification_provenance(qualified.provenance)
    store.save_incident_id_registry(qualified.incident_id_registry)
    save_snapshot_provenance(
        store.load_items(), store.load_incidents(), operation="BACKFILL_UNKNOWNS",
    )
    site.build()
    print(f"Qualification finale : {qualified.changes}; incidents={len(incidents)}.")
    return 0


def _print_sector_llm_report(report) -> None:
    print(f"  Organisations sélectionnées : {report.organisations_selected}")
    print(f"  Cache hits                  : {report.cache_hits}")
    print(f"  Cache misses                : {report.cache_misses}")
    print(f"  Appels LLM                  : {report.calls}")
    print(f"  Candidats                   : {report.candidates}")
    print(f"  Abstentions                 : {report.abstentions}")
    print(f"  Coût estimé                 : {report.cost_usd:.4f} USD")
    print(f"  LLM disponible              : {report.llm_available}")
    if report.dry_run:
        print("  DRY-RUN : aucune écriture, aucun appel réseau.")
    elif report.candidates:
        print(
            f"  Cache mis à jour : {len(report.cache_rows)} organisation(s) au total "
            f"-> data/organisation_sector_llm.csv"
        )
        print("  Exécuter ensuite `python -m cyberwatch replay` pour appliquer.")
    else:
        print("  Aucun nouveau candidat : cache inchangé.")


def cmd_sector_llm(args) -> int:
    """Complète par LLM organisationnel les organisations encore Inconnu (§26).

    Étape explicite et réseau, jamais appelée par ``qualify()``/``replay``.
    """
    items = store.load_items()
    if not items:
        print("Aucun item en base : exécuter d'abord CREATE.")
        return 1
    report = organisation_sector_llm.enrich_unknown_organisation_sectors(
        items, reference=enrichment.load_reference(),
    )
    print("SECTOR-LLM")
    _print_sector_llm_report(report)
    return 0


def cmd_sector_backfill(args) -> int:
    """Backfill historique du reliquat Sector, avec options explicites (§27)."""
    items = store.load_items()
    if not items:
        print("Aucun item en base : exécuter d'abord CREATE.")
        return 1
    organisation_keys = None
    if args.organisation_key:
        organisation_keys = {organisation_key(args.organisation_key)}
    report = organisation_sector_llm.enrich_unknown_organisation_sectors(
        items,
        reference=enrichment.load_reference(),
        limit=args.limit,
        organisation_keys=organisation_keys,
        dry_run=args.dry_run,
        force=args.force_llm,
        no_llm=args.no_llm,
    )
    print("SECTOR-BACKFILL")
    _print_sector_llm_report(report)
    return 0


def cmd_test_repeat(args) -> int:
    """Test de répétabilité du §27 : deux constructions, quatre égalités."""
    items = store.load_items()
    if not items:
        # Base neuve : il n'y a rien à comparer, ce n'est pas un échec.
        # La répétabilité du moteur reste couverte par tests/test_identity.py,
        # qui s'exécute sur des jeux de données figés.
        print("TEST REPETABILITE (§27)")
        print("  Base vide : test de répétabilité sur snapshot sans objet.")
        print("  ATTENTION : cela ne prouve pas la répétabilité d’un snapshot réel.")
        print("  Le moteur reste couvert par les tests unitaires sur fixtures.")
        return 0

    registry = store.load_incident_id_registry()
    build_a, registry_a = build_incidents_with_registry(items, registry)
    hash_items_a = identity.items_hash(items)
    hash_incidents_a = identity.incidents_hash(build_a)

    shuffled = list(items)
    random.Random(20260812).shuffle(shuffled)
    build_b, registry_b = build_incidents_with_registry(shuffled, registry)
    hash_items_b = identity.items_hash(shuffled)
    hash_incidents_b = identity.incidents_hash(build_b)

    checks = [
        ("Nombre d'items", len(items), len(shuffled)),
        ("Items_Hash", hash_items_a, hash_items_b),
        ("Nombre d'incidents", len(build_a), len(build_b)),
        ("Incidents_Hash", hash_incidents_a, hash_incidents_b),
        ("Registre Incident_ID", registry_a, registry_b),
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


def cmd_baseline(args) -> int:
    """Enregistre le snapshot courant, déjà validé, comme référence locale."""
    if cmd_check(args) != 0:
        return 1
    if cmd_test_repeat(args) != 0:
        print("Baseline refusée : test-repeat en échec.")
        return 1
    snapshot = store.load_snapshot()
    expected_sources = sorted(spec.source_id for spec in sources.ALL_SOURCES if spec.active)
    baseline = {
        "Baseline": True,
        "Validated_At": args.as_of or snapshot.get("As_Of", ""),
        "Code_Commit": snapshot.get("Code_Commit", ""),
        "Run_ID": snapshot.get("Run_ID", ""),
        "As_Of": snapshot.get("As_Of", ""),
        "Target_Start": snapshot.get("Target_Start", ""),
        "Target_End": snapshot.get("Target_End", ""),
        "Sources_Active": expected_sources,
        "Items_Count": snapshot.get("Items_Count", 0),
        "Incidents_Count": snapshot.get("Incidents_Count", 0),
        "Items_Hash": snapshot.get("Items_Hash", ""),
        "Incidents_Hash": snapshot.get("Incidents_Hash", ""),
    }
    store.save_baseline(baseline)
    print("Baseline enregistrée.")
    return 0


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
    territories = watchlists.entity_territories()

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
            client, spec, context, known_orgs, entity_index, territories
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


def cmd_probe(args) -> int:
    """Détaille, pour une source, ce que chaque méthode d'accès a répondu.

    Complète `diagnose`, qui dit *qu'une* source échoue : `probe` dit *pourquoi*,
    étape par étape de la chaîne d'accès. C'est l'outil à lancer quand une source
    passe en `FAIL` et qu'il faut décider quoi corriger.
    """
    from urllib.parse import urljoin

    from .collectors.feed import COMMON_FEED_PATHS, discover_feeds, parse_feed
    from .collectors.jsonld import (
        PAGINATION_PATTERNS,
        extract_jsonld_entries,
        extract_time_tag_entries,
        page_url,
    )
    from .collectors.wordpress import discover_endpoint, origin_of

    spec = sources.by_id(args.source)
    if spec is None:
        print(f"Source inconnue : {args.source}")
        print("Sources disponibles :")
        for candidate in sources.ALL_SOURCES:
            print(f"  - {candidate.source_id}")
        return 1

    context = make_run_context(MODE_DIAGNOSE, args.as_of, args.start)
    window = context.window
    client = HttpClient(run_budget=Budget(120, 300))
    budget = client.source_budget()

    print(f"PROBE {spec.source_id}")
    print(f"  URL de départ : {spec.start_url}")
    print(f"  Fenêtre       : {window.start} -> {window.end}")
    print()

    print("robots.txt")
    print(f"  chemin autorisé : {client.allowed(spec.start_url)}")
    print()

    print("1. Page de départ")
    first = client.fetch(spec.start_url, budget)
    print(f"  HTTP {first.status_code} · {len(first.text)} octets · {first.reason_code}")
    if first.ok:
        head = first.text[:400].replace("\n", " ")
        print(f"  début : {head[:180]}…")
    print()

    print("2. API REST WordPress")
    endpoint = discover_endpoint(client, spec.start_url, budget)
    if endpoint:
        print(f"  détectée : {endpoint}")
        probe = client.fetch(f"{endpoint}/posts?per_page=3", budget)
        payload = probe.json()
        print(f"  HTTP {probe.status_code} · "
              f"{len(payload) if isinstance(payload, list) else 'corps non liste'} articles")
        print(f"  X-WP-TotalPages : {probe.headers.get('X-WP-TotalPages', 'absent')}")
        if isinstance(payload, list) and payload:
            post = payload[0]
            print(f"  exemple : {post.get('date')} — "
                  f"{(post.get('title') or {}).get('rendered', '')[:70]}")
    else:
        print("  non disponible")
    print()

    print("3. Flux RSS / Atom")
    # Une source peut déclarer son flux de référence. Le probe doit tester ce
    # contrat exact au lieu de fabriquer des URLs à partir de son chemin RSS.
    explicit_feed = spec.params.get("feed_url")
    candidates = [explicit_feed] if explicit_feed else discover_feeds(
        client, spec.start_url, budget
    )[:6]
    for feed_url in candidates:
        response = client.fetch(feed_url, budget)
        if not response.ok:
            print(f"  HTTP {response.status_code:3} · {feed_url}")
            continue
        entries = parse_feed(response.text, spec)
        oldest = min((e.published for e in entries), default="")
        print(f"  HTTP 200 · {len(entries):3} entrées · plus ancienne {oldest or '—'} "
              f"· {feed_url}")
        if entries:
            print(f"    exemple : {entries[0].published} — {entries[0].title[:70]}")
            break
    print()

    print("4. JSON-LD et balises time")
    if first.ok:
        jsonld = extract_jsonld_entries(first.text, spec.start_url, spec)
        timed = extract_time_tag_entries(first.text, spec.start_url, spec)
        print(f"  JSON-LD  : {len(jsonld)} entrées datées")
        if jsonld:
            print(f"    exemple : {jsonld[0].published} — {jsonld[0].title[:70]}")
        print(f"  <time>   : {len(timed)} entrées datées")
        if timed:
            print(f"    exemple : {timed[0].published} — {timed[0].title[:70]}")
        blocks = first.text.count("application/ld+json")
        print(f"  blocs ld+json présents dans la page : {blocks}")
        print(f"  balises <time> présentes : {first.text.count('<time')}")
    else:
        print("  page de départ inaccessible")
    print()

    print("5. Pagination")
    for pattern in PAGINATION_PATTERNS:
        url = page_url(spec.start_url, pattern, 2)
        response = client.fetch(url, budget)
        marker = "identique à la page 1" if response.ok and response.text == first.text else ""
        print(f"  HTTP {response.status_code:3} · {url} {marker}")
    print()

    print(f"Total requêtes : {budget.requests_made}")
    return 0


def cmd_probe_media(args) -> int:
    """Teste, média par média, quel chemin d'accès offre le plus d'historique.

    Les couches de veille lisent aujourd'hui les flux RSS, qui ne portent que
    quelques semaines. Un média sous WordPress expose en revanche une API REST
    filtrable par date, donc tout son historique. Cette commande dit lesquels
    l'offrent, et jusqu'où chacun remonte réellement.
    """
    from .collectors.base import SourceSpec
    from .collectors.feed import discover_feeds, parse_feed
    from .collectors.wordpress import discover_endpoint

    domains: list[tuple[str, str]] = []
    for spec in sources.ALL_SOURCES:
        for domain in spec.params.get("domains") or []:
            if (spec.zone, domain) not in domains:
                domains.append((spec.zone, domain))
    if args.only:
        wanted = {d.strip() for d in args.only.split(",")}
        selected = [(z, d) for z, d in domains if d in wanted]
        # Les sources directes n'ont pas forcément `params.domains`. Accepter
        # leur Source_ID rend le probe réutilisable sans les déguiser en watcher.
        for spec in sources.ALL_SOURCES:
            if spec.source_id in wanted and spec.start_url:
                candidate = (spec.zone, spec.start_url)
                if candidate not in selected:
                    selected.append(candidate)
        domains = selected

    context = make_run_context(MODE_DIAGNOSE, args.as_of, args.start)
    window = context.window
    # Une vingtaine de requêtes par média : découverte de l'API, puis essai des
    # chemins de flux conventionnels. Le budget est dimensionné pour que le
    # dernier média sondé le soit aussi complètement que le premier.
    client = HttpClient(run_budget=Budget(40 * max(1, len(domains)), 1500))

    print(f"PROBE MEDIA — fenêtre {window.start} -> {window.end}")
    print(f"{len(domains)} médias à sonder")
    print()
    header = f"{'Média':34} {'Territoire':14} {'API WP':7} {'Flux':6} {'Remonte au':12} Détail"
    print(header)
    print("-" * len(header))

    usable = []
    for zone, domain in domains:
        base = domain if domain.startswith("http") else f"https://{domain}/"
        budget = client.source_budget()
        spec = SourceSpec("PROBE", "X", zone, base, "autodetect")

        endpoint = discover_endpoint(client, base, budget)
        wp_depth, wp_count, detail = "", 0, ""
        if endpoint:
            url = (f"{endpoint}/posts?per_page=100&orderby=date&order=asc"
                   f"&after={window.start}T00:00:00&_fields=id,date")
            response = client.fetch(url, budget)
            payload = response.json() if response.ok else None
            if isinstance(payload, list) and payload:
                from .normalize import parse_date

                wp_count = len(payload)
                wp_depth = parse_date(payload[0].get("date"))
                pages = response.headers.get("X-WP-TotalPages", "?")
                detail = f"{pages} page(s) sur la fenêtre"
            elif response.ok:
                detail = "API présente mais aucun article sur la fenêtre"
            else:
                detail = f"API présente, lecture {response.reason_code}"

        feed_depth = ""
        for feed_url in discover_feeds(client, base, budget)[:4]:
            response = client.fetch(feed_url, budget)
            if not response.ok:
                continue
            entries = parse_feed(response.text, spec)
            if entries:
                feed_depth = min(e.published for e in entries if e.published)
                break

        deepest = wp_depth or feed_depth
        print(f"{domain[:33]:34} {zone[:13]:14} "
              f"{'oui' if endpoint else 'non':7} {'oui' if feed_depth else 'non':6} "
              f"{deepest or '—':12} {detail}")
        if wp_depth:
            usable.append((domain, wp_depth, wp_count))

    print()
    if usable:
        print("Médias exposant une API WordPress exploitable :")
        for domain, depth, count in usable:
            print(f"  {domain:34} historique jusqu'au {depth}, {count}+ articles")
        print()
        print("-> basculer ces médias sur le collecteur WordPress rouvrirait "
              "l'historique complet, là où leur flux ne porte que quelques semaines.")
    else:
        print("Aucun média n'expose d'API WordPress exploitable : la veille reste "
              "limitée à la profondeur des flux.")
    print()
    print(f"Total requêtes : {client.run_budget.requests_made}")
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
    icon = {"OK": "🟢", "BROKEN": "🔴"}.get(overall, "⚪")

    print(f"## {icon} {overall} — {last.get('Mode', '')} `{run_id}`")
    print()
    print(f"- Fenêtre : `{last.get('Target_Start')}` → `{last.get('Target_End')}`")
    print(f"- Couches : `{last.get('Layers', '')}`")
    print(f"- Items : **{last.get('Items_Count')}** (+{last.get('New_Items')} nouveaux)")
    print(f"- Incidents : **{last.get('Incidents_Count')}** "
          f"(+{last.get('New_Incidents')} nouveaux)")
    print(f"- Sources : **{last.get('Sources_OK', 0)} OK / {last.get('Sources_FAIL', 0)} FAIL**")
    print(f"- Statut global : **{overall}**")
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

    ai_usage = next(
        (r for r in reversed(store.read_csv(store.AI_USAGE_CSV)) if r.get("Run_ID") == run_id),
        None,
    )
    if ai_usage:
        print()
        print("### Qualification IA")
        print()
        print(f"- Candidats : **{ai_usage.get('Candidates', 0)}** "
              f"(cache : {ai_usage.get('Cache_Hits', 0)})")
        print(f"- Appels API : **{ai_usage.get('Calls_Succeeded', 0)} réussis / "
              f"{ai_usage.get('Calls_Failed', 0)} échoués / "
              f"{ai_usage.get('Calls_Budget_Blocked', 0)} bloqués par budget** "
              f"(tentés : {ai_usage.get('Calls_Attempted', 0)})")
        print(f"- Tokens : {ai_usage.get('Input_Tokens', 0)} entrée / "
              f"{ai_usage.get('Output_Tokens', 0)} sortie "
              f"({ai_usage.get('Total_Tokens', 0)} total)")
        print(f"- Coût estimé : **${ai_usage.get('Estimated_Cost_USD', 0)}** "
              f"({ai_usage.get('Model', '')})")
        print(f"- Qualifiés : Threat {ai_usage.get('Threat_Qualified', 0)} · "
              f"Sector {ai_usage.get('Sector_Qualified', 0)} · "
              f"Location {ai_usage.get('Location_Qualified', 0)}")
        print(f"- Encore Inconnu après IA : **{ai_usage.get('Still_Unknown', 0)}**")
        print(f"- Statut : **{ai_usage.get('Status', '')}**")
        if ai_usage.get("Sector_Initial_Unknown"):
            print(
                f"- Secteur (§12) : {ai_usage.get('Sector_Initial_Unknown', 0)} inconnus initiaux → "
                f"référentiel {ai_usage.get('Sector_Resolved_Reference', 0)} · "
                f"règles {ai_usage.get('Sector_Resolved_Deterministic', 0)} · "
                f"contexte source {ai_usage.get('Sector_Resolved_Source_LLM', 0)} · "
                f"enrichi {int(ai_usage.get('Sector_Resolved_Enriched_Deterministic', 0) or 0) + int(ai_usage.get('Sector_Resolved_Enriched_LLM', 0) or 0)} "
                f"→ **{ai_usage.get('Sector_Remaining_Unknown', 0)} restants**"
            )
            print(
                f"- Enrichissement gratuit : {ai_usage.get('Org_Enrichment_Calls', 0)} appels HTTP, "
                f"taux de cache {ai_usage.get('Org_Enrichment_Cache_Hit_Rate', 0)}"
            )

    dedup_ai_usage = next(
        (r for r in reversed(store.load_dedup_ai_daily_usage()) if r.get("Run_ID") == run_id),
        None,
    )
    if dedup_ai_usage:
        print()
        print("### Filet LLM déduplication (quotidien)")
        print()
        print(f"- Statut : **{dedup_ai_usage.get('Status', '')}**")
        print(
            f"- Candidats : **{dedup_ai_usage.get('Candidates_Generated', 0)}** générés, "
            f"{dedup_ai_usage.get('Candidates_Selected', 0)} sélectionnés, "
            f"{dedup_ai_usage.get('Candidates_Not_Reviewed_Capacity', 0)} non revus (capacité)"
        )
        print(
            f"- Appels LLM : **{dedup_ai_usage.get('LLM_Calls', 0)}** "
            f"({dedup_ai_usage.get('LLM_Calls_Succeeded', 0)} réussis / "
            f"{dedup_ai_usage.get('LLM_Calls_Failed', 0)} échoués, "
            f"cache : {dedup_ai_usage.get('LLM_Cache_Hits', 0)})"
        )
        print(
            f"- Décisions : SAME organisation {dedup_ai_usage.get('LLM_Same_Organisation', 0)} · "
            f"SAME incident {dedup_ai_usage.get('LLM_Same_Incident', 0)} · "
            f"DIFFERENT {dedup_ai_usage.get('LLM_Different', 0)} · "
            f"UNKNOWN {dedup_ai_usage.get('LLM_Unknown', 0)}"
        )
        print(f"- Alias d'identité appliqués : **{dedup_ai_usage.get('Org_Aliases_Applied', 0)}**")
        print(
            f"- Coût estimé : **${dedup_ai_usage.get('LLM_Cost_USD', 0)}** "
            f"en {dedup_ai_usage.get('LLM_Duration_Seconds', 0)}s "
            f"({dedup_ai_usage.get('Model', '')})"
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


def cmd_audit_duplicates(args) -> int:
    """Affiche les rapprochements d'organisations à examiner, sans mutation."""
    candidates = find_duplicate_candidates(store.load_items(), max_days=args.max_days)
    print(f"Audit doublons potentiels — {len(candidates)} candidat(s), aucun rapprochement appliqué.")
    for candidate in candidates:
        short, long = candidate.short, candidate.long
        print()
        print(f"- Nom court : {short.Organisation_Raw} ({short.Organisation_Key})")
        print(f"  Nom long  : {long.Organisation_Raw} ({long.Organisation_Key})")
        print(f"  Dates     : {short.best_date} / {long.best_date} (écart {candidate.days_apart} j)")
        print(f"  Menaces   : {short.Threat} / {long.Threat}")
        print(f"  Sources   : {short.Source_ID} / {long.Source_ID}")
        print(f"  URLs      : {short.URL} | {long.URL}")
        print(f"  Motif     : {candidate.reason_code} — sources différentes, date compatible")
    return 0


def cmd_check(args) -> int:
    base_state, state_problems = store.snapshot_state()
    if base_state == store.BASE_UNINITIALIZED:
        print("Contrôles avant export (§29) — BASE NON INITIALISÉE")
        if getattr(args, "allow_uninitialized", False):
            print("  PASS : aucune donnée partielle n'est présente.")
            return 0
        print("  ! Snapshot Cyberwatch absent : exécuter d'abord CREATE.")
        return 1
    if base_state == store.BASE_INCOHERENT:
        print("Contrôles avant export (§29) — BASE INCOHÉRENTE / INITIALISATION INCOMPLÈTE")
        for problem in state_problems:
            print(f"  ! {problem}")
        return 1

    items = store.load_items()
    incidents = store.load_incidents()
    problems = pre_export_checks(items, incidents, [])
    registry = store.load_incident_id_registry()
    if not registry and incidents:
        # Compatibilité de migration : un snapshot antérieur au registre
        # reste vérifiable uniquement si chaque ID publié permet de retrouver
        # son ancre de manière exacte et non ambiguë. Rien n'est écrit ici.
        try:
            registry = incident_identity.bootstrap_registry(items, incidents)
        except ValueError as error:
            problems.append(f'Registre Incident_ID non migrable : {error}')
    problems.extend(incident_identity.validate_registry(registry, items, incidents))
    # Les contrôles portant sur RUN_SOURCES ne s'appliquent pas hors run.
    problems = [p for p in problems if "RUN_SOURCES" not in p]

    last = store.load_run_log()
    if last:
        row = last[-1]
        if not row.get("Items_Hash") or not row.get("Incidents_Hash"):
            problems.append("Les hashes du dernier run sont absents")
    if len({row.get("Run_ID", "") for row in last}) != len(last):
        problems.append("Run_ID dupliqué dans RUN_LOG")
    run_sources = store.load_run_sources()
    pairs = [(row.get("Run_ID", ""), row.get("Source_ID", "")) for row in run_sources]
    if len(set(pairs)) != len(pairs):
        problems.append("Couple Run_ID / Source_ID dupliqué dans RUN_SOURCES")
    if any(not item.Organisation_Key for item in items):
        problems.append("Organisation_Key vide dans ITEMS")
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
        sub.add_argument(
            "--transient", action="store_true",
            help="Exécuter sans écrire snapshot, historiques ni dashboard.",
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

    repair = subparsers.add_parser(
        "repair-identities", help="Appliquer les corrections déterministes aux ITEMS existants."
    )
    repair.set_defaults(func=cmd_repair_identities)

    integrity = subparsers.add_parser(
        "repair-integrity", help="Réparer IDs et doublons de clé exacte sans réseau."
    )
    integrity.set_defaults(func=cmd_repair_integrity)

    backfill = subparsers.add_parser(
        "backfill-unknowns", help="Compléter uniquement Menace/Localisation inconnues."
    )
    backfill.set_defaults(func=cmd_backfill_unknowns)

    sector_llm = subparsers.add_parser(
        "sector-llm",
        help="Compléter par LLM organisationnel les organisations Inconnu récentes.",
    )
    sector_llm.set_defaults(func=cmd_sector_llm)

    sector_backfill = subparsers.add_parser(
        "sector-backfill",
        help="Backfill historique du reliquat Sector (P0 puis LLM sur cache miss).",
    )
    sector_backfill.add_argument("--limit", type=int, default=None, help="Nombre maximal d'organisations traitées.")
    sector_backfill.add_argument("--organisation-key", default="", help="Ne traiter qu'une seule organisation.")
    sector_backfill.add_argument("--no-llm", action="store_true", help="Calculer P0 et le cache existant, sans appeler le LLM.")
    sector_backfill.add_argument("--force-llm", action="store_true", help="Ignorer un cache hit existant et redemander un candidat.")
    sector_backfill.add_argument("--dry-run", action="store_true", help="Simuler sans aucune écriture ni appel réseau.")
    sector_backfill.set_defaults(func=cmd_sector_backfill)

    repeat = subparsers.add_parser("test-repeat", help="Test de répétabilité (§27).")
    repeat.set_defaults(func=cmd_test_repeat)

    baseline = subparsers.add_parser("baseline", help="Enregistrer la baseline du snapshot validé.")
    baseline.add_argument("--as-of", dest="as_of", help="Date de validation ISO 8601.")
    baseline.set_defaults(func=cmd_baseline)

    diagnose = subparsers.add_parser(
        "diagnose", help="Sonder les sources et mesurer le coût réel."
    )
    add_common(diagnose)
    diagnose.add_argument("--only", help="Ne sonder qu'une seule source.")
    diagnose.set_defaults(func=cmd_diagnose)

    build = subparsers.add_parser("build-site", help="Régénérer les données du site.")
    build.set_defaults(func=cmd_build_site)

    duplicate_audit = subparsers.add_parser(
        "audit-duplicates", help="Signaler des doublons potentiels sans les fusionner."
    )
    duplicate_audit.add_argument(
        "--max-days", type=int, default=3,
        help="Écart maximal entre dates, en jours (défaut : 3).",
    )
    duplicate_audit.set_defaults(func=cmd_audit_duplicates)

    report = subparsers.add_parser("report", help="Résumé Markdown du dernier run.")
    report.set_defaults(func=cmd_report)

    probe = subparsers.add_parser(
        "probe", help="Détailler ce que chaque méthode d'accès répond pour une source."
    )
    probe.add_argument("source", help="Source_ID à sonder.")
    add_common(probe, with_layers=False)
    probe.set_defaults(func=cmd_probe)

    probe_media = subparsers.add_parser(
        "probe-media",
        help="Comparer, média par média, la profondeur offerte par l'API "
             "WordPress et par le flux RSS.",
    )
    probe_media.add_argument(
        "--only", help="Ne sonder que ces domaines (séparés par des virgules)."
    )
    add_common(probe_media, with_layers=False)
    probe_media.set_defaults(func=cmd_probe_media)

    check = subparsers.add_parser("check", help="Rejouer les contrôles du §29.")
    check.add_argument(
        "--allow-uninitialized", action="store_true",
        help="Accepter uniquement une base totalement neuve pour la CI code.",
    )
    check.set_defaults(func=cmd_check)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
