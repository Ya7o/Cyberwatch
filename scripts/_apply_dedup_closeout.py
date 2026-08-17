#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def patch(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"pattern not found in {path}: {old[:120]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


# store.py
patch(
    "cyberwatch/store.py",
    "from .source_llm_fallback import QUALIFICATION_PROVENANCE_COLUMNS\n",
    "from .source_llm_fallback import QUALIFICATION_PROVENANCE_COLUMNS\n"
    "from .incident_identity import REGISTRY_COLUMNS\n",
)
patch(
    "cyberwatch/store.py",
    'ORG_ENRICHMENT_CACHE_CSV = DATA_DIR / "org_enrichment_cache.csv"\n',
    'ORG_ENRICHMENT_CACHE_CSV = DATA_DIR / "org_enrichment_cache.csv"\n'
    'INCIDENT_ID_REGISTRY_CSV = DATA_DIR / "incident_id_registry.csv"\n',
)
patch(
    "cyberwatch/store.py",
    "def save_incidents(incidents: list[Incident], path: Path | None = None) -> None:\n"
    "    write_csv(\n"
    "        path or INCIDENTS_CSV,\n"
    "        INCIDENT_COLUMNS,\n"
    "        [incident.to_row() for incident in incidents],\n"
    "    )\n\n\n",
    "def save_incidents(incidents: list[Incident], path: Path | None = None) -> None:\n"
    "    write_csv(\n"
    "        path or INCIDENTS_CSV,\n"
    "        INCIDENT_COLUMNS,\n"
    "        [incident.to_row() for incident in incidents],\n"
    "    )\n\n\n"
    "def load_incident_id_registry(path: Path | None = None) -> list[dict]:\n"
    "    return read_csv(path or INCIDENT_ID_REGISTRY_CSV)\n\n\n"
    "def save_incident_id_registry(rows: list[dict], path: Path | None = None) -> None:\n"
    "    ordered = sorted(rows, key=lambda row: (row.get('Incident_ID', ''), row.get('Anchor_Item_ID', '')))\n"
    "    write_csv(path or INCIDENT_ID_REGISTRY_CSV, REGISTRY_COLUMNS, ordered)\n\n\n",
)

# dedup.py
patch(
    "cyberwatch/dedup.py",
    "from .identity import incident_id, sort_incidents, sort_items\n",
    "from .identity import incident_id, sort_incidents, sort_items\n"
    "from .incident_identity import assign_incident_ids, component_identity_key\n",
)
old_build = '''def build_incidents(items: list[Item]) -> list[Incident]:
    incidents: list[Incident] = []
    for component in group_components(items):
        ordered = sort_items(component)
        evidence = _incident_evidence_items(ordered)
        date, basis = _component_dates(ordered)
        component_key = _effective_key(ordered[0])
        # Une résolution d'identité ne doit pas renommer un incident qui ne
        # fusionne avec rien. Pour une vraie composante multi-items, la clé
        # résolue devient en revanche l'identité stable de la fusion.
        incident_key = (
            ordered[0].Organisation_Key or component_key
            if len(ordered) == 1
            else component_key
        )
        incidents.append(Incident(
            Incident_ID=incident_id(incident_key, ordered[0].Item_ID),
            Date=date,
            Date_Basis=basis,
            Organisation=_majority(
                [item.Organisation_Raw for item in ordered],
                ordered[0].Organisation_Raw or "",
            ),
            Secteur=_preferred_qualification(ordered, "Sector", config.SECTOR_UNKNOWN),
            Menace=_priority_threat([item.Threat for item in ordered]),
            Localisation=_preferred_qualification(ordered, "Location", config.LOC_INCONNU),
            Sources=" | ".join(sorted({item.Source_ID for item in evidence if item.Source_ID})),
            Source_URLs=" | ".join(sorted({item.URL for item in evidence if item.URL})),
            Items_Count=len(ordered),
            First_seen=min(
                (item.Collected_As_Of for item in ordered if item.Collected_As_Of),
                default="",
            ),
            Last_seen=max(
                (item.Collected_As_Of for item in ordered if item.Collected_As_Of),
                default="",
            ),
        ))
    return sort_incidents(incidents)
'''
new_build = '''def _incident_from_component(component: list[Item], stable_id: str = "") -> Incident:
    ordered = sort_items(component)
    evidence = _incident_evidence_items(ordered)
    date, basis = _component_dates(ordered)
    incident_key = component_identity_key(ordered)
    return Incident(
        Incident_ID=stable_id or incident_id(incident_key, ordered[0].Item_ID),
        Date=date,
        Date_Basis=basis,
        Organisation=_majority(
            [item.Organisation_Raw for item in ordered],
            ordered[0].Organisation_Raw or "",
        ),
        Secteur=_preferred_qualification(ordered, "Sector", config.SECTOR_UNKNOWN),
        Menace=_priority_threat([item.Threat for item in ordered]),
        Localisation=_preferred_qualification(ordered, "Location", config.LOC_INCONNU),
        Sources=" | ".join(sorted({item.Source_ID for item in evidence if item.Source_ID})),
        Source_URLs=" | ".join(sorted({item.URL for item in evidence if item.URL})),
        Items_Count=len(ordered),
        First_seen=min(
            (item.Collected_As_Of for item in ordered if item.Collected_As_Of),
            default="",
        ),
        Last_seen=max(
            (item.Collected_As_Of for item in ordered if item.Collected_As_Of),
            default="",
        ),
    )


def build_incidents_with_registry(
    items: list[Item], registry_rows: list[dict] | None = None,
) -> tuple[list[Incident], list[dict[str, str]]]:
    """Construit INCIDENTS en conservant les ancres historiques persistées."""
    components = group_components(items)
    assigned, updated_registry = assign_incident_ids(components, registry_rows)
    incidents = [
        _incident_from_component(component, stable_id)
        for component, stable_id in zip(components, assigned)
    ]
    return sort_incidents(incidents), updated_registry


def build_incidents(items: list[Item]) -> list[Incident]:
    """Construction pure sans état, utilisée par les tests de règles de dédup."""
    return sort_incidents([
        _incident_from_component(component)
        for component in group_components(items)
    ])
'''
patch("cyberwatch/dedup.py", old_build, new_build)

# qualification.py
patch(
    "cyberwatch/qualification.py",
    "from .dedup import build_incidents\n",
    "from .dedup import build_incidents_with_registry\n",
)
patch(
    "cyberwatch/qualification.py",
    "    provenance: list[dict[str, str]]\n    items_hash: str\n",
    "    provenance: list[dict[str, str]]\n    incident_id_registry: list[dict[str, str]]\n    items_hash: str\n",
)
patch(
    "cyberwatch/qualification.py",
    "    incidents = build_incidents(ordered)\n    return QualificationReport(\n",
    "    incidents, incident_id_registry = build_incidents_with_registry(\n"
    "        ordered, store.load_incident_id_registry()\n"
    "    )\n    return QualificationReport(\n",
)
patch(
    "cyberwatch/qualification.py",
    "        provenance=provenance,\n        items_hash=identity.items_hash(ordered),\n",
    "        provenance=provenance,\n        incident_id_registry=incident_id_registry,\n        items_hash=identity.items_hash(ordered),\n",
)

# runner.py
patch(
    "cyberwatch/runner.py",
    "from . import ai, config, enrichment, identity, org_enrichment, sector as sector_policy, source_facts, sources, status, store, watchlists\n",
    "from . import ai, config, enrichment, identity, incident_identity, org_enrichment, sector as sector_policy, source_facts, sources, status, store, watchlists\n",
)
patch(
    "cyberwatch/runner.py",
    "    qualification_provenance: list[dict] = field(default_factory=list)\n",
    "    qualification_provenance: list[dict] = field(default_factory=list)\n"
    "    incident_id_registry: list[dict] = field(default_factory=list)\n",
)
patch(
    "cyberwatch/runner.py",
    "    report.qualification_provenance = qualified.provenance\n    report.new_incidents = len([i for i in report.incidents if i.Incident_ID not in previous_ids])\n",
    "    report.qualification_provenance = qualified.provenance\n"
    "    report.incident_id_registry = qualified.incident_id_registry\n"
    "    report.new_incidents = len([i for i in report.incidents if i.Incident_ID not in previous_ids])\n",
)
patch(
    "cyberwatch/runner.py",
    "    report.problems = pre_export_checks(report.items, report.incidents, report.outcomes, selected_source_ids)\n",
    "    report.problems = pre_export_checks(report.items, report.incidents, report.outcomes, selected_source_ids)\n"
    "    report.problems.extend(incident_identity.validate_registry(\n"
    "        report.incident_id_registry, report.items, report.incidents\n"
    "    ))\n",
)
patch(
    "cyberwatch/runner.py",
    "            store.save_items(report.items)\n            store.save_incidents(report.incidents)\n            save_snapshot_provenance(\n",
    "            store.save_items(report.items)\n            store.save_incidents(report.incidents)\n"
    "            store.save_incident_id_registry(report.incident_id_registry)\n"
    "            save_snapshot_provenance(\n",
)
patch(
    "cyberwatch/runner.py",
    "        store.save_incidents(report.incidents)\n        store.save_source_facts(report.source_facts)\n",
    "        store.save_incidents(report.incidents)\n"
    "        store.save_incident_id_registry(report.incident_id_registry)\n"
    "        store.save_source_facts(report.source_facts)\n",
)

# cli.py
patch(
    "cyberwatch/cli.py",
    "from . import config, enrichment, identity, site, sources, status, store\n",
    "from . import config, enrichment, identity, incident_identity, site, sources, status, store\n",
)
patch(
    "cyberwatch/cli.py",
    "from .dedup import build_incidents\n",
    "from .dedup import build_incidents, build_incidents_with_registry\n",
)
patch(
    "cyberwatch/cli.py",
    "    incidents = build_incidents(items)\n    store.save_items(identity.sort_items(items))\n    store.save_incidents(incidents)\n",
    "    incidents, registry = build_incidents_with_registry(items, store.load_incident_id_registry())\n"
    "    store.save_items(identity.sort_items(items))\n"
    "    store.save_incidents(incidents)\n"
    "    store.save_incident_id_registry(registry)\n",
)
# second occurrence, repair-integrity
patch(
    "cyberwatch/cli.py",
    "    incidents = build_incidents(items)\n    problems = pre_export_checks(items, incidents, [])\n",
    "    incidents, registry = build_incidents_with_registry(items, store.load_incident_id_registry())\n"
    "    problems = pre_export_checks(items, incidents, [])\n"
    "    problems.extend(incident_identity.validate_registry(registry, items, incidents))\n",
)
patch(
    "cyberwatch/cli.py",
    "    store.save_items(items)\n    store.save_incidents(incidents)\n    save_snapshot_provenance(\n",
    "    store.save_items(items)\n    store.save_incidents(incidents)\n"
    "    store.save_incident_id_registry(registry)\n"
    "    save_snapshot_provenance(\n",
)
patch(
    "cyberwatch/cli.py",
    "    store.save_qualification_provenance(qualified.provenance)\n    save_snapshot_provenance(\n",
    "    store.save_qualification_provenance(qualified.provenance)\n"
    "    store.save_incident_id_registry(qualified.incident_id_registry)\n"
    "    save_snapshot_provenance(\n",
)
patch(
    "cyberwatch/cli.py",
    "    build_a = build_incidents(items)\n    hash_items_a = identity.items_hash(items)\n    hash_incidents_a = identity.incidents_hash(build_a)\n\n    shuffled = list(items)\n",
    "    registry = store.load_incident_id_registry()\n"
    "    build_a, registry_a = build_incidents_with_registry(items, registry)\n"
    "    hash_items_a = identity.items_hash(items)\n"
    "    hash_incidents_a = identity.incidents_hash(build_a)\n\n"
    "    shuffled = list(items)\n",
)
patch(
    "cyberwatch/cli.py",
    "    build_b = build_incidents(shuffled)\n    hash_items_b = identity.items_hash(shuffled)\n    hash_incidents_b = identity.incidents_hash(build_b)\n",
    "    build_b, registry_b = build_incidents_with_registry(shuffled, registry)\n"
    "    hash_items_b = identity.items_hash(shuffled)\n"
    "    hash_incidents_b = identity.incidents_hash(build_b)\n",
)
patch(
    "cyberwatch/cli.py",
    "        (\"Incidents_Hash\", hash_incidents_a, hash_incidents_b),\n    ]\n",
    "        (\"Incidents_Hash\", hash_incidents_a, hash_incidents_b),\n"
    "        (\"Registre Incident_ID\", registry_a, registry_b),\n"
    "    ]\n",
)
patch(
    "cyberwatch/cli.py",
    "    problems = pre_export_checks(items, incidents, [])\n    # Les contrôles portant sur RUN_SOURCES ne s'appliquent pas hors run.\n",
    "    problems = pre_export_checks(items, incidents, [])\n"
    "    problems.extend(incident_identity.validate_registry(\n"
    "        store.load_incident_id_registry(), items, incidents\n"
    "    ))\n"
    "    # Les contrôles portant sur RUN_SOURCES ne s'appliquent pas hors run.\n",
)

print("dedup closeout patch applied")
