"""Orchestration d'un run : collecte, normalisation, reconstruction, journaux.

Le runner applique les algorithmes `CREATE` (§24), `MAJ` (§25) et `REPLAY` (§26),
et produit les journaux `RUN_SOURCES` et `RUN_LOG` ainsi que l'état de veille
`ENTITY_WATCH`.

Principe de robustesse : **aucune source ne peut faire échouer un run**. Toute
exception est convertie en statut `FAIL` documenté, et les données déjà
collectées sont conservées.
"""

from __future__ import annotations

import datetime as dt
import time
from dataclasses import dataclass, field

from . import config, enrichment, identity, sources, status, store, watchlists
from .collectors import get_collector
from .collectors.base import RawEntry, SourceSpec, Window
from .dedup import build_incidents, merge_items
from .http import Budget, HttpClient
from .model import Incident, Item
from .normalize import (
    classify_location,
    searchable,
    classify_sector,
    classify_threat,
    clean_organisation,
    find_known_entity,
    looks_cyber,
    organisation_from_entry_title,
    organisation_from_title,
    organisation_key,
)

MODE_CREATE = "CREATE"
MODE_MAJ = "MAJ"
MODE_REPLAY = "REPLAY"
MODE_DIAGNOSE = "DIAGNOSE"


@dataclass
class RunContext:
    """Paramètres figés au début du run (§6)."""

    run_id: str
    as_of: str
    target_start: str
    target_end: str
    mode: str
    layers: list[str]
    method_id: str = config.METHOD_ID

    @property
    def window(self) -> Window:
        return Window(self.target_start, self.target_end)


def make_run_context(
    mode: str,
    as_of: str | None = None,
    target_start: str | None = None,
    layers: list[str] | None = None,
) -> RunContext:
    """Fige les paramètres du run.

    `CREATE` sans période démarre au 1er janvier de l'année de `AS_OF` (§6).
    `MAJ` rejoue volontairement les 30 derniers jours depuis le dernier run, ce
    chevauchement permettant de récupérer ajouts tardifs et corrections.
    """
    now = (
        dt.datetime.fromisoformat(as_of)
        if as_of
        else dt.datetime.now(dt.timezone(dt.timedelta(hours=4)))
    )
    as_of_iso = now.isoformat()
    end = now.date().isoformat()

    if target_start:
        start = target_start
    elif mode == MODE_MAJ:
        previous = _last_run_as_of()
        anchor = previous or now.date()
        start = (anchor - dt.timedelta(days=config.MAJ_OVERLAP_DAYS)).isoformat()
    else:
        start = dt.date(now.year, 1, 1).isoformat()

    base_run_id = now.strftime("RUN-%Y%m%dT%H%M%S")
    existing_run_ids = {row.get("Run_ID", "") for row in store.load_run_log()}
    sequence = 1
    run_id = base_run_id
    while run_id in existing_run_ids:
        sequence += 1
        run_id = f"{base_run_id}-{sequence}"
    return RunContext(
        run_id=run_id,
        as_of=as_of_iso,
        target_start=start,
        target_end=end,
        mode=mode,
        layers=layers or config.LAYER_GROUPS["all"],
    )


def _last_run_as_of() -> dt.date | None:
    """Date du dernier run enregistré, ou `None` si la base est neuve."""
    rows = store.load_run_log()
    if not rows:
        return None
    stamps = sorted(row.get("As_Of", "") for row in rows if row.get("As_Of"))
    if not stamps:
        return None
    try:
        return dt.datetime.fromisoformat(stamps[-1]).date()
    except ValueError:
        return None


# --------------------------------------------------------------------------
# Normalisation d'une entrée brute en item
# --------------------------------------------------------------------------


def entry_to_item(
    entry: RawEntry,
    spec: SourceSpec,
    as_of: str,
    known_orgs: dict[str, str],
    entity_index: dict,
    territories: dict[str, str] | None = None,
    reference: dict[str, enrichment.Enrichment] | None = None,
) -> Item | None:
    """Convertit une entrée brute en item normalisé, ou `None` si hors périmètre.

    Un contenu sans aucun marqueur cyber n'entre pas dans la base, même
    lorsqu'il provient d'une rubrique cyber : c'est le garde-fou qui empêche la
    rubrique « Numérique » d'un média local de tout déverser dans `ITEMS`.
    """
    territories = territories or {}

    if not entry.published:
        return None

    text = f"{entry.title} {entry.summary}"

    # Le garde-fou de vocabulaire protège des rubriques généralistes, où tout
    # n'est pas cyber. Il ne s'applique pas aux sources dont le périmètre entier
    # l'est déjà — liste de fuites, de victimes de rançongiciel, ou catégorie
    # « attaque » d'un site spécialisé : leur périmètre fait foi, et l'exiger en
    # plus écarterait des titres pourtant sans ambiguïté (« les données de 1 000
    # employés diffusées publiquement »).
    scope_is_cyber = spec.default_threat or spec.params.get("scope_is_cyber")
    if not scope_is_cyber and not looks_cyber(text):
        return None

    # Organisation : fournie par la source, sinon lue dans le titre, sinon
    # reconnue parmi les entités surveillées. Jamais devinée.
    organisation = clean_organisation(entry.organisation) or organisation_from_title(
        entry.title
    )

    # Certaines sources publient l'organisation comme titre de l'entrée : les
    # chronologies de fuites et les listes de victimes nomment chaque entrée
    # d'après l'organisation touchée (§13.1, §13.2). La règle est déclarée par
    # la source, elle n'est pas déduite de la forme du titre.
    if not organisation and spec.params.get("title_is_organisation"):
        organisation = organisation_from_entry_title(entry.title)

    if not organisation:
        organisation = find_known_entity(text, known_orgs)

    # Kwezi mesure tous les articles de rubrique, mais ne matérialise dans
    # ITEMS que ceux dont la victime est déterminée sans heuristique variable.
    if spec.source_id == "KWEZI_NUMERIQUE" and not organisation:
        return None

    sector_hint = ""
    if entry.entity:
        watched = entity_index.get(entry.entity)
        if watched is not None:
            sector_hint = watched.sector_hint

    threat = classify_threat(text, default=spec.default_threat)

    # Le secteur est celui de la victime (§9). Le nom de l'organisation est donc
    # examiné avant le corps de l'article : celui-ci décrit l'incident, pas le
    # métier de la victime, et un simple mot y suffirait à la reclasser à tort.
    # Lorsque la source nomme ses entrées d'après l'organisation, le corps n'est
    # qu'une description de la fuite : on ne s'y rabat pas du tout.
    # Les champs structurés de la source passent toujours en premier. Le
    # référentiel dédié vient ensuite ; les règles et défauts existants ne sont
    # consultés qu'en dernier recours.
    sector = classify_sector(given=entry.sector)
    location = classify_location(given=entry.location)
    sector, location = enrichment.enrich_unknowns(organisation, sector, location, reference or {})

    sector_texts = (organisation,) if spec.params.get("title_is_organisation") else (organisation, text)
    if sector == config.SECTOR_UNKNOWN:
        sector = classify_sector(*sector_texts, given=sector_hint)
    if location == config.LOC_INCONNU:
        location = classify_location(
            text, organisation,
            entity=territories.get(searchable(organisation), ""),
            default=spec.location_rule,
        )

    key = organisation_key(organisation)

    return Item(
        Item_ID=identity.item_id(
            spec.source_id,
            entry.published,
            key,
            entry.url,
            entry.source_item_id,
        ),
        Source_ID=spec.source_id,
        Source_Item_ID=entry.source_item_id,
        Published_Date=entry.published,
        Event_Date=entry.event_date,
        Organisation_Raw=organisation,
        Organisation_Key=key,
        Threat_Raw=entry.threat,
        Threat=threat,
        Sector=sector,
        Location=location,
        Title=entry.title,
        URL=entry.url,
        Collected_As_Of=as_of,
    )


# --------------------------------------------------------------------------
# Exécution d'une source
# --------------------------------------------------------------------------


def run_source(
    client: HttpClient,
    spec: SourceSpec,
    context: RunContext,
    known_orgs: dict[str, str],
    entity_index: dict,
    territories: dict[str, str] | None = None,
    reference: dict[str, enrichment.Enrichment] | None = None,
) -> tuple[status.SourceOutcome, list[Item], list[dict]]:
    """Exécute une source et rend son compte rendu, ses items et sa veille."""
    outcome = status.SourceOutcome(source_id=spec.source_id, layer=spec.layer)

    if not spec.active:
        outcome.status = status.SKIPPED
        outcome.coverage = 0
        outcome.reason_code = status.REASON_SOURCE_INACTIVE
        return outcome, [], []

    if spec.layer not in context.layers:
        outcome.status = status.SKIPPED
        outcome.coverage = 0
        outcome.reason_code = status.REASON_LAYER_NOT_SCHEDULED
        return outcome, [], []

    started = time.monotonic()
    collector = get_collector(spec.collector)

    try:
        result = collector.collect(client, spec, context.window)
    except Exception as exc:  # aucune source ne doit interrompre le run
        outcome.status = status.FAIL
        outcome.coverage = 0
        outcome.reason_code = status.REASON_PARSE_ERROR
        outcome.comment = f"{type(exc).__name__}: {exc}"[:300]
        outcome.duration_seconds = round(time.monotonic() - started, 1)
        return outcome, [], []

    items: list[Item] = []
    for entry in result.entries:
        item = entry_to_item(
            entry, spec, context.as_of, known_orgs, entity_index, territories, reference
        )
        if item is not None:
            items.append(item)

    source_status, coverage = result.resolve()
    outcome.status = source_status
    outcome.coverage = coverage
    outcome.reason_code = result.reason_code
    outcome.units_done = result.units_done
    outcome.units_expected = result.units_expected
    outcome.calls = result.calls
    outcome.items_seen = result.items_seen if result.items_seen is not None else len(result.entries)
    outcome.items_collected = len(items)
    outcome.access_method = result.access_method
    outcome.comment = result.comment
    outcome.duration_seconds = round(time.monotonic() - started, 1)
    outcome.latest_item_date = max((i.Published_Date for i in items), default="")

    watch_rows = []
    for row in result.watch_rows:
        row["source_id"] = spec.source_id
        watch_rows.append(row)

    return outcome, items, watch_rows


# --------------------------------------------------------------------------
# État de veille par entité
# --------------------------------------------------------------------------


def build_entity_watch(
    watch_rows: list[dict],
    incidents: list[Incident],
    as_of: str,
    previous: list[dict],
) -> list[dict]:
    """Construit `ENTITY_WATCH` : une ligne par entité sous surveillance.

    Les entités non interrogées lors de ce run conservent leur état précédent,
    de sorte que le tableau du dashboard reste complet et montre explicitement
    la date de dernière interrogation de chacune.
    """
    from .normalize import searchable

    previous_by_entity = {row.get("Entity", ""): row for row in previous}
    queried = {row["entity"]: row for row in watch_rows}

    # Dernier incident connu par organisation normalisée.
    last_incident: dict[str, Incident] = {}
    for incident in incidents:
        key = searchable(incident.Organisation)
        current = last_incident.get(key)
        if current is None or incident.Date > current.Date:
            last_incident[key] = incident

    rows = []
    for entity in watchlists.ALL_ENTITIES:
        previous_row = previous_by_entity.get(entity.name, {})
        result = queried.get(entity.name)

        if result:
            last_queried = as_of
            query_status = result["status"]
            items_found = result["items_found"]
        else:
            last_queried = previous_row.get("Last_Queried", "")
            query_status = previous_row.get("Query_Status", status.SKIPPED)
            items_found = previous_row.get("Items_Found", 0)

        incident = last_incident.get(searchable(entity.name))
        for alias in entity.aliases:
            if incident is not None:
                break
            incident = last_incident.get(searchable(alias))

        rows.append(
            {
                "Entity": entity.name,
                "Entity_Key": organisation_key(entity.name),
                "Territory": entity.territory,
                "Type": entity.kind,
                "Sector_Hint": entity.sector_hint,
                "Last_Queried": last_queried,
                "Query_Status": query_status,
                "Items_Found": items_found,
                "Last_Incident_Date": incident.Date if incident else "",
                "Last_Incident_ID": incident.Incident_ID if incident else "",
            }
        )

    return sorted(rows, key=lambda row: (row["Territory"], row["Type"], row["Entity"]))


# --------------------------------------------------------------------------
# Contrôles avant export (§29)
# --------------------------------------------------------------------------


def pre_export_checks(
    items: list[Item],
    incidents: list[Incident],
    outcomes: list[status.SourceOutcome],
) -> list[str]:
    """Contrôles du §29. Renvoie la liste des anomalies détectées."""
    problems: list[str] = []

    item_ids = [i.Item_ID for i in items]
    if len(item_ids) != len(set(item_ids)):
        problems.append("Item_ID dupliqué détecté dans ITEMS")

    incident_ids = [i.Incident_ID for i in incidents]
    if len(incident_ids) != len(set(incident_ids)):
        problems.append("Incident_ID dupliqué détecté dans INCIDENTS")

    for incident in incidents:
        if not incident.Sources:
            problems.append(f"Incident sans source : {incident.Incident_ID}")

    seen_sources = {o.source_id for o in outcomes}
    for spec in sources.ALL_SOURCES:
        if spec.active and spec.source_id not in seen_sources:
            problems.append(f"Source active sans ligne RUN_SOURCES : {spec.source_id}")

    for outcome in outcomes:
        if outcome.status == status.OK and outcome.coverage < 100:
            problems.append(
                f"Statut OK sans couverture complète : {outcome.source_id}"
            )

    return problems


# --------------------------------------------------------------------------
# Run complet
# --------------------------------------------------------------------------


@dataclass
class RunReport:
    """Résultat d'un run, destiné à l'affichage et aux journaux."""

    context: RunContext
    outcomes: list[status.SourceOutcome] = field(default_factory=list)
    items: list[Item] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)
    new_items: int = 0
    new_incidents: int = 0
    items_hash: str = ""
    incidents_hash: str = ""
    overall: str = status.HEALTHY
    health: int = 0
    problems: list[str] = field(default_factory=list)
    duration: float = 0.0
    requests: int = 0


def execute(context: RunContext, offline: bool = False) -> RunReport:
    """Exécute un run complet et écrit la base.

    `offline=True` correspond au mode `REPLAY` (§26) : aucun accès Web, on
    reconstruit `INCIDENTS` à partir du snapshot `ITEMS` existant.
    """
    started = time.monotonic()
    report = RunReport(context=context)

    previous_incidents = store.load_incidents()
    previous_ids = {i.Incident_ID for i in previous_incidents}

    # `CREATE` construit la base **depuis zéro** (§24) : le snapshot `ITEMS`
    # précédent n'est pas repris. C'est ce qui permet de repartir proprement
    # après une évolution des règles de normalisation, laquelle change les
    # `Item_ID` et laisserait sinon cohabiter chaque item avec sa version
    # périmée. `MAJ` conserve au contraire le stock et n'y ajoute que le
    # nouveau (§25).
    existing_items = [] if context.mode == MODE_CREATE else store.load_items()
    existing_item_ids = {item.Item_ID for item in existing_items}

    if offline:
        report.items = existing_items
    else:
        run_budget = Budget(
            config.MAX_REQUESTS_PER_RUN, config.MAX_SECONDS_PER_RUN, "run"
        )
        client = HttpClient(run_budget=run_budget)
        known_orgs = watchlists.known_organisations()
        entity_index = watchlists.entity_index()
        territories = watchlists.entity_territories()
        reference = enrichment.load_reference()

        collected: list[Item] = []
        watch_rows: list[dict] = []

        # V0 mono-source : ne jamais exécuter ni journaliser les collecteurs
        # désactivés ; le pipeline doit appeler exactement BonjourLaFuite.
        for spec in sources.active_sources(context.layers):
            outcome, items, rows = run_source(
                client, spec, context, known_orgs, entity_index, territories, reference
            )
            report.outcomes.append(outcome)
            collected.extend(items)
            watch_rows.extend(rows)
            # Écriture immédiate du compte rendu, comme l'exige le §24.7.
            print(
                f"  {outcome.source_id:28} {outcome.status:8} "
                f"{outcome.coverage:3}%  items={outcome.items_collected:4} "
                f"calls={outcome.calls:4}  {outcome.reason_code}"
            )

        merged, new_count = merge_items(existing_items, collected)
        for outcome in report.outcomes:
            outcome.new_items = sum(
                item.Source_ID == outcome.source_id and item.Item_ID not in existing_item_ids
                for item in collected
            )
            outcome.items_collected = sum(
                item.Source_ID == outcome.source_id for item in merged
            )
        report.items = merged
        report.new_items = new_count
        report.requests = run_budget.requests_made

    report.incidents = build_incidents(report.items)
    report.new_incidents = len(
        [i for i in report.incidents if i.Incident_ID not in previous_ids]
    )
    report.items_hash = identity.items_hash(report.items)
    report.incidents_hash = identity.incidents_hash(report.incidents)
    report.health = 100 if report.outcomes and all(o.status == status.OK for o in report.outcomes) else 0
    report.overall = "OK" if report.health == 100 else status.BROKEN
    report.problems = pre_export_checks(
        report.items, report.incidents, report.outcomes
    )
    report.duration = round(time.monotonic() - started, 1)

    _persist(report, watch_rows if not offline else [])
    return report


def _persist(report: RunReport, watch_rows: list[dict]) -> None:
    """Écrit la base, les journaux et l'état de veille."""
    context = report.context

    store.save_items(report.items)
    store.save_incidents(report.incidents)
    store.save_sources(sources.to_rows())

    if report.outcomes:
        store.append_run_sources(
            [
                {
                    "Run_ID": context.run_id,
                    "As_Of": context.as_of,
                    "Source_ID": o.source_id,
                    "Layer": o.layer,
                    "Status": o.status,
                    "Coverage": o.coverage,
                    "Reason_Code": o.reason_code,
                    "Reason": o.reason,
                    "Calls": o.calls,
                    "Units_Done": o.units_done,
                    "Units_Expected": o.units_expected,
                    "Items_seen": o.items_seen,
                    "Items_in_window": o.units_done,
                    "Items_collected": o.items_collected,
                    "New_items": o.new_items,
                    "Latest_item_date": o.latest_item_date,
                    "Access_Method": o.access_method,
                    "Duration_s": o.duration_seconds,
                    "Comment": o.comment,
                }
                for o in report.outcomes
            ]
        )

        store.save_entity_watch(
            build_entity_watch(
                watch_rows,
                report.incidents,
                context.as_of,
                store.load_entity_watch(),
            )
        )

    # REPLAY est une transformation locale : il ne constitue pas une collecte
    # et ne doit donc pas remplacer l'état OK/FAIL de la dernière collecte.
    if not report.outcomes:
        return

    counts = status.status_counts(report.outcomes)
    store.append_run_log(
        {
            "Run_ID": context.run_id,
            "As_Of": context.as_of,
            "Mode": context.mode,
            "Method_ID": context.method_id,
            "Target_Start": context.target_start,
            "Target_End": context.target_end,
            "Layers": ",".join(context.layers),
            "Items_Count": len(report.items),
            "Incidents_Count": len(report.incidents),
            "New_Items": report.new_items,
            "New_Incidents": report.new_incidents,
            "Source_Status": "OK" if report.overall == "OK" else status.FAIL,
            "Items_seen": sum(o.items_seen for o in report.outcomes),
            "Items_in_window": sum(o.units_done for o in report.outcomes),
            "Sources_OK": counts.get(status.OK, 0),
            "Sources_PARTIAL": counts.get(status.PARTIAL, 0),
            "Sources_FAIL": counts.get(status.FAIL, 0),
            "Sources_SKIPPED": counts.get(status.SKIPPED, 0),
            "Items_Hash": report.items_hash,
            "Incidents_Hash": report.incidents_hash,
            "Overall_Status": report.overall,
            "Duration_s": report.duration,
            "Requests": report.requests,
            "Notes": " ; ".join(report.problems),
        }
    )
