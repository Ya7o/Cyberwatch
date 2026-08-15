from pathlib import Path
from textwrap import dedent


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"motif introuvable dans {path}: {old[:120]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


collector = dedent('''\
"""Import déterministe du snapshot JSON produit par Veille LLM.

La source est analytique : elle peut ajouter ou enrichir un incident, mais ne
constitue pas une corroboration éditoriale indépendante lorsqu'une source
directe couvre déjà le même événement.
"""

from __future__ import annotations

import json

from .. import store
from ..normalize import date_or_empty
from .base import CollectResult, Collector, RawEntry, SourceSpec, Window


class VeilleLlmCollector(Collector):
    """Lit le snapshot complet pour inclure les découvertes historiques tardives."""

    name = "veillellm"

    def collect(self, client, spec: SourceSpec, window: Window) -> CollectResult:
        relative = str(spec.params.get("path") or "").strip()
        if not relative:
            raise ValueError("Chemin Veille LLM absent")

        root = store.ROOT.resolve()
        path = (root / relative).resolve()
        if root not in path.parents:
            raise ValueError("Chemin Veille LLM hors dépôt")
        if not path.is_file():
            raise FileNotFoundError(relative)

        data = json.loads(path.read_text(encoding="utf-8"))
        metadata = data.get("metadata") or {}
        records = data.get("incidents")
        if not isinstance(records, list):
            raise ValueError("incidents doit être une liste")

        declared = metadata.get("record_count")
        if declared is not None and int(declared) != len(records):
            raise ValueError(
                f"record_count incohérent: {declared} déclaré, {len(records)} lu"
            )

        min_score = int(spec.params.get("min_score", 50))
        entries: list[RawEntry] = []
        weak = 0
        future = 0
        requested_window_hits = 0

        for index, record in enumerate(records, start=1):
            if not isinstance(record, dict):
                raise ValueError(f"incident #{index} invalide")

            date = str(record.get("date") or "").strip()
            organisation = str(record.get("organisation") or "").strip()
            territory = str(record.get("territoire") or "").strip()
            threat = str(record.get("type_menace") or "").strip()
            if date_or_empty(date) is None:
                raise ValueError(f"date invalide incident #{index}: {date!r}")
            if not organisation or not territory or not threat:
                raise ValueError(f"champs obligatoires absents incident #{index}")

            raw_score = record.get("score_cyberattaque")
            if isinstance(raw_score, bool):
                raise ValueError(f"score invalide incident #{index}")
            try:
                score = int(raw_score)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"score invalide incident #{index}") from exc
            if not 0 <= score <= 100:
                raise ValueError(f"score hors bornes incident #{index}: {score}")

            evidence = record.get("sources") or []
            if not isinstance(evidence, list) or not evidence:
                raise ValueError(f"aucune source de référence incident #{index}")
            evidence = [
                str(url).strip() for url in evidence
                if str(url).strip().startswith(("https://", "http://"))
            ]
            if not evidence:
                raise ValueError(f"aucune URL de référence valide incident #{index}")

            if date > window.end:
                future += 1
                continue
            if score < min_score:
                weak += 1
                continue
            if window.contains(date):
                requested_window_hits += 1

            summary_parts = [
                str(record.get("statut") or "").strip(),
                str(record.get("synthese") or "").strip(),
                str(record.get("impact_connu") or "").strip(),
                f"Score Veille LLM: {score}/100",
            ]
            actor = str(record.get("acteur") or "").strip()
            if actor:
                summary_parts.append(f"Acteur: {actor}")

            entries.append(RawEntry(
                title=f"{organisation} : {threat}",
                url=spec.start_url,
                published=date,
                event_date=date,
                organisation=organisation,
                sector=str(record.get("secteur") or "").strip(),
                location=territory,
                threat=threat,
                summary=". ".join(part for part in summary_parts if part),
                content="Références documentaires: " + " | ".join(evidence),
            ))

        return CollectResult(
            entries=entries,
            reached_boundary=True,
            units_done=len(records),
            units_expected=len(records),
            calls=0,
            access_method="repository_json",
            comment=(
                f"snapshot_records={len(records)}; accepted={len(entries)}; "
                f"weak_below_{min_score}={weak}; future={future}; "
                f"requested_window_hits={requested_window_hits}"
            ),
            items_seen=len(records),
            items_in_window=requested_window_hits,
        )
''')
Path("cyberwatch/collectors/veillellm.py").write_text(collector, encoding="utf-8")

replace_once(
    "cyberwatch/collectors/__init__.py",
    "from .wordpress import WordPressCollector\n",
    "from .wordpress import WordPressCollector\nfrom .veillellm import VeilleLlmCollector\n",
)
replace_once(
    "cyberwatch/collectors/__init__.py",
    '    "kwezi": KweziCollector,\n',
    '    "kwezi": KweziCollector,\n    "veillellm": VeilleLlmCollector,\n',
)

source_block = dedent('''\
REGIONAL_WATCH_SOURCES = [
    SourceSpec(
        source_id="VEILLE_LLM",
        layer=config.LAYER_REGIONAL_WATCH,
        zone="La Réunion / Mayotte",
        start_url="https://github.com/Ya7o/Cyberwatch/blob/main/sources/veillellm/cyberattaques_reunion_mayotte_2026.json",
        collector="veillellm",
        active=True,
        location_rule=config.LOC_INCONNU,
        params={
            "path": "sources/veillellm/cyberattaques_reunion_mayotte_2026.json",
            "min_score": 50,
            "scope_is_cyber": True,
            "replace_snapshot": True,
            "non_evidence_source": True,
            "dashboard_filter": "veille_llm",
        },
        protocol=(
            "Lire le snapshot JSON versionné complet à chaque run ; valider le schéma, "
            "le record_count et les URLs de référence ; importer les dossiers dont le "
            "score cyberattaque est >= 50, y compris les découvertes historiques tardives."
        ),
        success_test=(
            "JSON valide, record_count cohérent, tous les dossiers structurés ; "
            "les signaux <50 restent hors INCIDENTS."
        ),
        notes=(
            "Source analytique issue de Veille LLM. Snapshot remplacé à chaque run ; "
            "elle ne compte pas comme corroboration éditoriale supplémentaire lorsqu'une "
            "source directe couvre déjà le même incident."
        ),
    ),
    _watch(
''')
replace_once(
    "cyberwatch/sources.py",
    "REGIONAL_WATCH_SOURCES = [\n    _watch(\n",
    source_block,
)

helper = dedent('''\

def _incident_evidence_items(ordered: list[Item]) -> list[Item]:
    """Écarte les apports analytiques du compteur de corroboration.

    Si un incident n'existe que dans une source analytique, celle-ci reste
    affichée comme source unique afin de ne jamais créer un incident sans source.
    """
    from . import sources

    evidence = []
    for item in ordered:
        spec = sources.by_id(item.Source_ID)
        if not (spec and spec.params.get("non_evidence_source")):
            evidence.append(item)
    return evidence or ordered
''')
replace_once(
    "cyberwatch/dedup.py",
    "\ndef build_incidents(items: list[Item]) -> list[Incident]:\n",
    helper + "\ndef build_incidents(items: list[Item]) -> list[Incident]:\n",
)
replace_once(
    "cyberwatch/dedup.py",
    "        ordered = sort_items(component)\n        date, basis = _component_dates(ordered)\n",
    "        ordered = sort_items(component)\n        evidence = _incident_evidence_items(ordered)\n        date, basis = _component_dates(ordered)\n",
)
replace_once(
    "cyberwatch/dedup.py",
    '            Sources=" | ".join(sorted({item.Source_ID for item in ordered if item.Source_ID})),\n            Source_URLs=" | ".join(sorted({item.URL for item in ordered if item.URL})),\n',
    '            Sources=" | ".join(sorted({item.Source_ID for item in evidence if item.Source_ID})),\n            Source_URLs=" | ".join(sorted({item.URL for item in evidence if item.URL})),\n',
)

replace_once(
    "cyberwatch/runner.py",
    "        merged, new_count = merge_items(existing_items, collected)\n",
    dedent('''\
        replacement_source_ids = {
            spec.source_id for spec in sources.active_sources(context.layers)
            if spec.params.get("replace_snapshot")
        }
        merge_base = [
            item for item in existing_items
            if item.Source_ID not in replacement_source_ids
        ]
        merged, _ = merge_items(merge_base, collected)
        new_count = sum(item.Item_ID not in existing_item_ids for item in collected)
''').replace("\n", "\n        ", 1).rstrip() + "\n",
)

replace_once(
    "cyberwatch/site.py",
    "from . import config, sources, status, store\nfrom .model import Incident\n",
    "from . import config, identity, sources, status, store\nfrom .dedup import group_components\nfrom .model import Incident, Item\n",
)
replace_once(
    "cyberwatch/site.py",
    'def incidents_payload(incidents: list[Incident]) -> list[dict]:\n    """Incidents au format compact attendu par le dashboard."""\n    payload = []\n',
    'def incidents_payload(incidents: list[Incident], provenance_tags: dict[str, list[str]] | None = None) -> list[dict]:\n    """Incidents au format compact attendu par le dashboard."""\n    provenance_tags = provenance_tags or {}\n    payload = []\n',
)
replace_once(
    "cyberwatch/site.py",
    '                "last_seen": incident.Last_seen,\n',
    '                "last_seen": incident.Last_seen,\n                "provenance_tags": provenance_tags.get(incident.Incident_ID, []),\n',
)

provenance_helper = dedent('''\

def _provenance_tags_by_incident(items: list[Item]) -> dict[str, list[str]]:
    """Expose les imports analytiques sans les transformer en corroboration."""
    payload: dict[str, list[str]] = {}
    for component in group_components(items):
        ordered = identity.sort_items(component)
        if not ordered:
            continue
        incident_id = identity.incident_id(
            ordered[0].Organisation_Key, ordered[0].Item_ID
        )
        tags = set()
        for item in ordered:
            spec = sources.by_id(item.Source_ID)
            tag = spec.params.get("dashboard_filter") if spec else ""
            if tag:
                tags.add(str(tag))
        if tags:
            payload[incident_id] = sorted(tags)
    return payload
''')
replace_once(
    "cyberwatch/site.py",
    "\ndef _source_metadata() -> dict[str, dict]:\n",
    provenance_helper + "\ndef _source_metadata() -> dict[str, dict]:\n",
)
replace_once(
    "cyberwatch/site.py",
    "    incidents = store.load_incidents()\n    payload = incidents_payload(incidents)\n",
    "    incidents = store.load_incidents()\n    items = store.load_items()\n    payload = incidents_payload(incidents, _provenance_tags_by_incident(items))\n",
)

replace_once(
    "assets/app-legacy.js",
    '      RANSOMWARE_LIVE: "Ransomware.live",\n',
    '      RANSOMWARE_LIVE: "Ransomware.live",\n      VEILLE_LLM: "Veille LLM",\n',
)
replace_once(
    "assets/app-legacy.js",
    '    const pressOnly = $("#f-presse-mahoraise")?.getAttribute("aria-pressed") === "true";\n    const press = pressOnly ? mahoranPressSources() : null;\n',
    '    const pressOnly = $("#f-presse-mahoraise")?.getAttribute("aria-pressed") === "true";\n    const veilleLlmOnly = $("#f-veille-llm")?.getAttribute("aria-pressed") === "true";\n    const press = pressOnly ? mahoranPressSources() : null;\n',
)
replace_once(
    "assets/app-legacy.js",
    "      if (press && !(incident.sources || []).some((source) => press.has(source))) return false;\n",
    "      if (press && !(incident.sources || []).some((source) => press.has(source))) return false;\n      if (veilleLlmOnly && !(incident.provenance_tags || []).includes(\"veille_llm\")) return false;\n",
)
replace_once(
    "assets/app-legacy.js",
    '      ["#f-presse-mahoraise", "Presse mahoraise"],\n',
    '      ["#f-presse-mahoraise", "Presse mahoraise"],\n      ["#f-veille-llm", "Veille LLM"],\n',
)
replace_once(
    "assets/app-legacy.js",
    '["#f-ocean-indien", "#f-auto", "#f-grande-distrib", "#f-presse-mahoraise"].forEach',
    '["#f-ocean-indien", "#f-auto", "#f-grande-distrib", "#f-presse-mahoraise", "#f-veille-llm"].forEach',
)

replace_once(
    "assets/dashboard-audit.js",
    '      RANSOMWARE_LIVE: "Ransomware.live",\n',
    '      RANSOMWARE_LIVE: "Ransomware.live",\n      VEILLE_LLM: "Veille LLM",\n',
)
replace_once(
    "assets/dashboard-audit.js",
    '    const pressOnly = $("#f-presse-mahoraise")?.getAttribute("aria-pressed") === "true";\n    const press = pressOnly ? mahoranPressSources() : null;\n',
    '    const pressOnly = $("#f-presse-mahoraise")?.getAttribute("aria-pressed") === "true";\n    const veilleLlmOnly = $("#f-veille-llm")?.getAttribute("aria-pressed") === "true";\n    const press = pressOnly ? mahoranPressSources() : null;\n',
)
replace_once(
    "assets/dashboard-audit.js",
    "      if (press && !(incident.sources || []).some((source) => press.has(source))) return false;\n",
    "      if (press && !(incident.sources || []).some((source) => press.has(source))) return false;\n      if (veilleLlmOnly && !(incident.provenance_tags || []).includes(\"veille_llm\")) return false;\n",
)

replace_once(
    "index.html",
    '    <button id="f-presse-mahoraise" class="btn-quick" type="button" aria-pressed="false">Presse mahoraise</button>\n',
    '    <button id="f-presse-mahoraise" class="btn-quick" type="button" aria-pressed="false">Presse mahoraise</button>\n    <button id="f-veille-llm" class="btn-quick" type="button" aria-pressed="false">Veille LLM</button>\n',
)

tests = dedent('''\
from cyberwatch import config, identity, site, sources
from cyberwatch.collectors import get_collector
from cyberwatch.collectors.base import Window
from cyberwatch.dedup import build_incidents
from cyberwatch.model import Item


def _item(source_id, org="STOR Solutions", date="2026-04-24", url="https://example.test/a"):
    key = "stor solutions"
    return Item(
        Item_ID=identity.item_id(source_id, date, key, url, ""),
        Source_ID=source_id,
        Published_Date=date,
        Event_Date=date,
        Organisation_Raw=org,
        Organisation_Key=key,
        Threat="Intrusion",
        Location=config.LOC_REUNION,
        URL=url,
    )


def test_veille_llm_source_is_active_analytical_snapshot():
    spec = sources.by_id("VEILLE_LLM")
    assert spec is not None and spec.active
    assert spec.collector == "veillellm"
    assert spec.layer == config.LAYER_REGIONAL_WATCH
    assert spec.params["replace_snapshot"] is True
    assert spec.params["non_evidence_source"] is True
    assert spec.params["dashboard_filter"] == "veille_llm"


def test_veille_llm_imports_full_snapshot_and_rejects_weak_signals():
    spec = sources.by_id("VEILLE_LLM")
    result = get_collector(spec.collector).collect(
        None, spec, Window("2026-07-25", "2026-08-15")
    )
    assert result.resolve() == ("OK", 100)
    assert result.items_seen == 8
    assert len(result.entries) == 6
    organisations = {entry.organisation for entry in result.entries}
    assert "Commune de Ouangani" not in organisations
    assert "Le Quotidien de La Réunion" not in organisations
    assert "Ville de Mamoudzou" in organisations
    assert all(
        entry.location in {config.LOC_REUNION, config.LOC_MAYOTTE}
        for entry in result.entries
    )


def test_veille_llm_does_not_inflate_direct_source_count():
    direct = _item("CYBERATTAQUE_ORG", url="https://www.cyberattaque.org/stor/")
    analytic = _item(
        "VEILLE_LLM",
        url="https://github.com/Ya7o/Cyberwatch/blob/main/sources/veillellm/cyberattaques_reunion_mayotte_2026.json",
    )
    incident = build_incidents([direct, analytic])[0]
    assert incident.Sources == "CYBERATTAQUE_ORG"
    assert incident.Items_Count == 2
    assert "veillellm" not in incident.Source_URLs.lower()


def test_veille_llm_remains_source_when_only_evidence():
    incident = build_incidents([_item("VEILLE_LLM")])[0]
    assert incident.Sources == "VEILLE_LLM"


def test_dashboard_payload_exposes_veille_llm_provenance_tag():
    item = _item("VEILLE_LLM")
    incident = build_incidents([item])[0]
    tags = site._provenance_tags_by_incident([item])
    payload = site.incidents_payload([incident], tags)[0]
    assert payload["provenance_tags"] == ["veille_llm"]


def test_dashboard_has_veille_llm_filter():
    html = open("index.html", encoding="utf-8").read()
    legacy = open("assets/app-legacy.js", encoding="utf-8").read()
    audit = open("assets/dashboard-audit.js", encoding="utf-8").read()
    assert 'id="f-veille-llm"' in html
    assert 'provenance_tags || []).includes("veille_llm")' in legacy
    assert 'provenance_tags || []).includes("veille_llm")' in audit
''')
Path("tests/test_veillellm.py").write_text(tests, encoding="utf-8")
