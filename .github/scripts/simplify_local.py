from __future__ import annotations

import ast
import re
from pathlib import Path
from textwrap import dedent

ROOT = Path(__file__).resolve().parents[2]

OBSOLETE_SOURCE_IDS = {
    "KWEZI_NUMERIQUE",
    "MAYOTTE_HEBDO_NUMERIQUE",
    "JOURNAL_DE_MAYOTTE",
    "MAYOTTE_FM",
    "MAYOTTE_LA_1ERE",
    "FLASH_INFOS_MAYOTTE",
    "LES_NOUVELLES_DE_MAYOTTE",
    "FRANCE_MAYOTTE_MATIN",
    "RMV_ACTUALITES",
    "MAYOTTE_ENTITY_WATCH",
    "MAYOTTE_MEDIA_WATCH",
}


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    (ROOT / path).write_text(text, encoding="utf-8")


def replace_once(path: str, old: str, new: str) -> None:
    text = read(path)
    if old not in text:
        raise RuntimeError(f"motif absent dans {path}: {old[:80]!r}")
    write(path, text.replace(old, new, 1))


def regex_once(path: str, pattern: str, replacement: str, flags: int = 0) -> None:
    text = read(path)
    updated, count = re.subn(pattern, replacement, text, count=1, flags=flags)
    if count != 1:
        raise RuntimeError(f"regex attendue une fois dans {path}: {pattern[:100]!r}, count={count}")
    write(path, updated)


def remove_source_calls(path: str, source_ids: set[str]) -> None:
    text = read(path)
    tree = ast.parse(text)
    lines = text.splitlines(keepends=True)
    ranges: list[tuple[int, int]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = node.func.id if isinstance(node.func, ast.Name) else ""
        source_id = ""
        if name == "SourceSpec":
            for kw in node.keywords:
                if kw.arg == "source_id" and isinstance(kw.value, ast.Constant):
                    source_id = str(kw.value.value)
                    break
            if not source_id and node.args and isinstance(node.args[0], ast.Constant):
                source_id = str(node.args[0].value)
        elif name == "_watch" and node.args and isinstance(node.args[0], ast.Constant):
            source_id = str(node.args[0].value)

        if source_id in source_ids:
            start = node.lineno - 1
            end = node.end_lineno or node.lineno
            ranges.append((start, end))

    if not ranges:
        raise RuntimeError(f"aucune SourceSpec/_watch supprimée dans {path}")

    drop: set[int] = set()
    for start, end in ranges:
        drop.update(range(start, end))
    write(path, "".join(line for i, line in enumerate(lines) if i not in drop))


# ---------------------------------------------------------------------------
# Sources : Veille LLM devient la seule source locale Réunion/Mayotte.
# ---------------------------------------------------------------------------
remove_source_calls("cyberwatch/sources.py", OBSOLETE_SOURCE_IDS)

sources_text = read("cyberwatch/sources.py")
sources_text = re.sub(
    r"\n# Lot 1 Mayotte :.*?MAYOTTE_CYBER_SEARCH_TERMS = list\(config\.MEDIA_SEARCH_TERMS\)\n",
    "\n",
    sources_text,
    flags=re.S,
)
sources_text = sources_text.replace('            "dashboard_filter": "veille_llm",\n', "")
sources_text = sources_text.replace(
    "Source analytique issue de Veille LLM. Snapshot remplacé à chaque run ; ",
    "Source locale analytique issue de Veille LLM pour La Réunion et Mayotte. Snapshot remplacé à chaque run ; ",
)
if "status." not in sources_text:
    sources_text = sources_text.replace("from . import config, status, watchlists", "from . import config, watchlists")
write("cyberwatch/sources.py", sources_text)

for source_id in OBSOLETE_SOURCE_IDS:
    if source_id in sources_text:
        raise RuntimeError(f"source obsolète encore déclarée: {source_id}")

# Ancien collecteur Kwezi et tests Lot 1 devenus inutiles.
for path in [
    "cyberwatch/collectors/kwezi.py",
    "tests/test_kwezi_content.py",
    "tests/test_kwezi_metrics.py",
    "tests/test_mayotte_local_coverage.py",
    "data/mayotte_media_inventory.csv",
]:
    target = ROOT / path
    if target.exists():
        target.unlink()

collectors = read("cyberwatch/collectors/__init__.py")
collectors = collectors.replace("from .kwezi import KweziCollector\n", "")
collectors = collectors.replace('    "kwezi": KweziCollector,\n', "")
write("cyberwatch/collectors/__init__.py", collectors)

runner = read("cyberwatch/runner.py")
runner = runner.replace("    organisation_from_kwezi_incident_text,\n", "")
runner = re.sub(
    r"\n    if not organisation and spec\.source_id == \"KWEZI_NUMERIQUE\":\n        organisation = organisation_from_kwezi_incident_text\(entry\.content\)\n",
    "\n",
    runner,
)
runner = runner.replace(
    "    # Kwezi mesure tous les articles de rubrique, mais ne matérialise dans\n"
    "    # ITEMS que ceux dont la victime est déterminée sans heuristique variable.\n",
    "    # Les sources qui exigent une victime ne matérialisent que les entrées\n"
    "    # dont la victime est déterminée sans heuristique variable.\n",
)
runner = runner.replace(
    "        # V0 mono-source : ne jamais exécuter ni journaliser les collecteurs\n"
    "        # désactivés ; le pipeline doit appeler exactement BonjourLaFuite.\n",
    "        # Exécuter uniquement les sources actives des couches demandées.\n",
)
write("cyberwatch/runner.py", runner)

# Les tests WordPress restent génériques : aucune référence à une source supprimée.
tests_collectors = read("tests/test_collectors.py").replace("KWEZI_NUMERIQUE", "TEST_LOCAL_MEDIA")
write("tests/test_collectors.py", tests_collectors)

write(
    "tests/test_collector_registry.py",
    dedent(
        '''\
        import pytest

        from cyberwatch import config, sources
        from cyberwatch.collectors import get_collector
        from cyberwatch.collectors.bonjourlafuite import BonjourLaFuiteCollector
        from cyberwatch.collectors.cyberattaque_org import CyberattaqueOrgCollector
        from cyberwatch.collectors.feed import FeedCollector
        from cyberwatch.collectors.ransomware_live import RansomwareLiveCollector
        from cyberwatch.collectors.veillellm import VeilleLlmCollector


        def test_active_sources_route_to_their_declared_collector():
            expected = {
                "BONJOURLAFUITE": BonjourLaFuiteCollector,
                "FRENCHBREACHES": FeedCollector,
                "CYBERATTAQUE_ORG": CyberattaqueOrgCollector,
                "RANSOMWARE_LIVE": RansomwareLiveCollector,
                "VEILLE_LLM": VeilleLlmCollector,
            }
            active = sources.active_sources()
            assert {spec.source_id for spec in active} == set(expected)
            for spec in active:
                assert type(get_collector(spec.collector)) is expected[spec.source_id]


        def test_frenchbreaches_uses_its_explicit_complete_rss_feed():
            spec = sources.by_id("FRENCHBREACHES")
            assert spec is not None
            assert spec.collector == "feed"
            assert spec.start_url == "https://frenchbreaches.com/feed.xml"
            assert spec.params["feed_url"] == spec.start_url


        def test_unknown_collector_fails_fast():
            with pytest.raises(ValueError, match="Collecteur inconnu : collecteur_inexistant"):
                get_collector("collecteur_inexistant")


        def test_source_ids_are_unique():
            ids = [spec.source_id for spec in sources.ALL_SOURCES]
            assert len(ids) == len(set(ids))


        def test_every_source_declares_a_known_layer():
            known_layers = {layer for group in config.LAYER_GROUPS.values() for layer in group} | {
                config.LAYER_DISABLED
            }
            for spec in sources.ALL_SOURCES:
                assert spec.layer in known_layers, f"{spec.source_id}: couche inconnue ({spec.layer})"


        def test_every_active_source_documents_protocol_and_success_test():
            for spec in sources.active_sources():
                assert spec.protocol, f"{spec.source_id}: protocole non documenté"
                assert spec.success_test, f"{spec.source_id}: test de succès non documenté"


        def test_full_scan_budget_stays_within_run_limit():
            budget = sum(sources.expected_units(spec) for spec in sources.active_sources())
            assert budget <= config.MAX_REQUESTS_PER_RUN
        '''
    ),
)

# ---------------------------------------------------------------------------
# Dashboard data : enrichissement structuré Local (synthèse, score, références).
# ---------------------------------------------------------------------------
site_text = read("cyberwatch/site.py")
site_text = site_text.replace("from __future__ import annotations\n\n", "from __future__ import annotations\n\nimport json\n\n", 1)
site_text = site_text.replace("from .model import Incident, Item\n", "from .model import Incident, Item\nfrom .normalize import organisation_key\n")

start = site_text.index("def incidents_payload(")
end = site_text.index("def _source_metadata()")
new_site_functions = dedent(
    '''\
    def incidents_payload(
        incidents: list[Incident],
        local_analysis: dict[str, dict] | None = None,
    ) -> list[dict]:
        """Incidents au format compact attendu par le dashboard."""
        local_analysis = local_analysis or {}
        payload = []
        for incident in incidents:
            row = {
                "id": incident.Incident_ID,
                "date": incident.Date,
                "basis": incident.Date_Basis,
                "org": incident.Organisation,
                "sector": incident.Secteur,
                "threat": incident.Menace,
                "location": incident.Localisation,
                "sources": [s for s in incident.Sources.split(" | ") if s],
                "urls": [u for u in incident.Source_URLs.split(" | ") if u],
                "items": incident.Items_Count,
                "first_seen": incident.First_seen,
                "last_seen": incident.Last_seen,
            }
            analysis = local_analysis.get(incident.Incident_ID)
            if analysis:
                row["local"] = analysis
            payload.append(row)
        return payload


    def _local_analysis_by_incident(items: list[Item]) -> dict[str, dict]:
        """Joint le snapshot Veille LLM aux incidents sans en faire une preuve éditoriale."""
        spec = sources.by_id("VEILLE_LLM")
        if spec is None:
            return {}
        relative = str(spec.params.get("path") or "").strip()
        if not relative:
            return {}
        path = (store.ROOT / relative).resolve()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return {}

        records = data.get("incidents") or []
        min_score = int(spec.params.get("min_score", 50))
        by_key: dict[tuple[str, str], dict] = {}
        for record in records:
            if not isinstance(record, dict):
                continue
            try:
                score = int(record.get("score_cyberattaque"))
            except (TypeError, ValueError):
                continue
            if score < min_score:
                continue
            organisation = str(record.get("organisation") or "").strip()
            date = str(record.get("date") or "").strip()
            summary = str(record.get("synthese") or "").strip()
            refs = record.get("sources") or []
            references = [
                str(url).strip() for url in refs
                if str(url).strip().startswith(("https://", "http://"))
            ]
            if not organisation or not date or not summary:
                continue
            by_key[(organisation_key(organisation), date)] = {
                "score": score,
                "summary": summary,
                "references": references,
            }

        payload: dict[str, dict] = {}
        for component in group_components(items):
            ordered = identity.sort_items(component)
            if not ordered:
                continue
            llm_items = [item for item in ordered if item.Source_ID == "VEILLE_LLM"]
            if not llm_items:
                continue
            incident_id = identity.incident_id(
                ordered[0].Organisation_Key, ordered[0].Item_ID
            )
            matches = []
            for item in llm_items:
                key = (item.Organisation_Key, item.Event_Date or item.Published_Date)
                analysis = by_key.get(key)
                if analysis:
                    matches.append(analysis)
            if matches:
                payload[incident_id] = max(
                    matches,
                    key=lambda value: (value["score"], value["summary"]),
                )
        return payload


    '''
)
site_text = site_text[:start] + new_site_functions + site_text[end:]
site_text = site_text.replace(
    "    payload = incidents_payload(incidents, _provenance_tags_by_incident(items))\n",
    "    payload = incidents_payload(incidents, _local_analysis_by_incident(items))\n",
)
write("cyberwatch/site.py", site_text)

# ---------------------------------------------------------------------------
# UI : filtre Local unique ; détails uniquement lorsque ce filtre est actif.
# ---------------------------------------------------------------------------
index = read("index.html")
index = re.sub(
    r'  <section class="quick-actions" aria-label="Actions rapides">.*?</section>',
    dedent(
        '''\
          <section class="quick-actions" aria-label="Actions rapides">
            <button id="f-ocean-indien" class="btn-quick" type="button" aria-pressed="false">Voir l’Océan Indien</button>
            <button id="f-auto" class="btn-quick" type="button" aria-pressed="false">Concessions automobiles</button>
            <button id="f-grande-distrib" class="btn-quick" type="button" aria-pressed="false">Grande distribution</button>
            <button id="f-local" class="btn-quick" type="button" aria-pressed="false">Local</button>
          </section>'''
    ).rstrip(),
    index,
    count=1,
    flags=re.S,
)
index = re.sub(r'\n\s*<details id="mayotte-coverage".*?</details>\n', "\n", index, count=1, flags=re.S)
write("index.html", index)

style = read("assets/style.css")
style = re.sub(r'\n\.mayotte-coverage \{.*?\.mayotte-coverage-group strong \{ color: var\(--text-primary\); \}\n', "\n", style, count=1, flags=re.S)
write("assets/style.css", style)

legacy = read("assets/app-legacy.js")
for line in [
    '      KWEZI_NUMERIQUE: "Kwezi",\n',
    '      MAYOTTE_HEBDO_NUMERIQUE: "Mayotte Hebdo",\n',
    '      JOURNAL_DE_MAYOTTE: "Journal de Mayotte",\n',
    '      MAYOTTE_FM: "Mayotte FM",\n',
    '      MAYOTTE_LA_1ERE: "Mayotte La 1ère",\n',
    '      FLASH_INFOS_MAYOTTE: "Flash Infos Mayotte",\n',
    '      FRANCE_MAYOTTE_MATIN: "France Mayotte Matin",\n',
    '      LES_NOUVELLES_DE_MAYOTTE: "Les Nouvelles de Mayotte",\n',
    '      RMV_ACTUALITES: "RMV Actualités",\n',
]:
    legacy = legacy.replace(line, "")
legacy = re.sub(
    r'\n  /\*\* Presse mahoraise directe.*?\n  function applyFilters\(incidents\) \{.*?\n  \}\n\n  function monthsRange',
    dedent(
        '''\

          function applyFilters(incidents) {
            const localOnly = $("#f-local")?.getAttribute("aria-pressed") === "true";
            return incidents.filter((incident) => {
              const ocean = $("#f-ocean-indien")?.getAttribute("aria-pressed") === "true";
              const automotive = $("#f-auto")?.getAttribute("aria-pressed") === "true";
              const largeRetail = $("#f-grande-distrib")?.getAttribute("aria-pressed") === "true";
              const oceanLocations = new Set(["La Réunion", "Mayotte", "Maurice", "Madagascar", "Seychelles", "Comores"]);
              if (ocean && !oceanLocations.has(incident.location)) return false;
              if (localOnly && !incident.local) return false;
              if ((automotive || largeRetail) && !(
                (automotive && AUTOMOTIVE_ORGS.has(orgKey(incident.org)))
                || (largeRetail && LARGE_RETAIL_ORGS.has(orgKey(incident.org)))
              )) return false;
              return true;
            });
          }

          function monthsRange'''
    ),
    legacy,
    count=1,
    flags=re.S,
)
legacy = re.sub(
    r'    const quickButtons = \[.*?\n    \];',
    dedent(
        '''\
            const quickButtons = [
              ["#f-ocean-indien", "Voir l’Océan Indien"],
              ["#f-auto", "Concessions automobiles"],
              ["#f-grande-distrib", "Grande distribution"],
              ["#f-local", "Local"],
            ];'''
    ).rstrip(),
    legacy,
    count=1,
    flags=re.S,
)
legacy = re.sub(
    r'\n  /\*\* Couverture presse mahoraise.*?\n  function render\(\) \{',
    "\n\n  function render() {",
    legacy,
    count=1,
    flags=re.S,
)
legacy = legacy.replace("    renderMayotteCoverage();\n", "")
legacy = legacy.replace(
    '["#f-ocean-indien", "#f-auto", "#f-grande-distrib", "#f-presse-mahoraise", "#f-veille-llm"]',
    '["#f-ocean-indien", "#f-auto", "#f-grande-distrib", "#f-local"]',
)
write("assets/app-legacy.js", legacy)

audit = read("assets/dashboard-audit.js")
audit = re.sub(
    r'  /\*\* Même dérivation qu\'app-legacy\.js.*?\n  \);\n',
    "",
    audit,
    count=1,
    flags=re.S,
)
for line in [
    '      KWEZI_NUMERIQUE: "Kwezi",\n',
    '      MAYOTTE_HEBDO_NUMERIQUE: "Mayotte Hebdo",\n',
    '      JOURNAL_DE_MAYOTTE: "Journal de Mayotte",\n',
    '      MAYOTTE_FM: "Mayotte FM",\n',
    '      MAYOTTE_LA_1ERE: "Mayotte La 1ère",\n',
    '      FLASH_INFOS_MAYOTTE: "Flash Infos Mayotte",\n',
    '      FRANCE_MAYOTTE_MATIN: "France Mayotte Matin",\n',
    '      LES_NOUVELLES_DE_MAYOTTE: "Les Nouvelles de Mayotte",\n',
    '      RMV_ACTUALITES: "RMV Actualités",\n',
]:
    audit = audit.replace(line, "")
audit = re.sub(
    r'  function filteredIncidents\(\) \{.*?\n  \}\n\n  function currentSort',
    dedent(
        '''\
          function filteredIncidents() {
            const localOnly = $("#f-local")?.getAttribute("aria-pressed") === "true";
            return state.incidents.filter((incident) => {
              const ocean = $("#f-ocean-indien")?.getAttribute("aria-pressed") === "true";
              const automotive = $("#f-auto")?.getAttribute("aria-pressed") === "true";
              const largeRetail = $("#f-grande-distrib")?.getAttribute("aria-pressed") === "true";
              const oceanLocations = new Set(["La Réunion", "Mayotte", "Maurice", "Madagascar", "Seychelles", "Comores"]);
              if (ocean && !oceanLocations.has(incident.location)) return false;
              if (localOnly && !incident.local) return false;
              if ((automotive || largeRetail) && !(
                (automotive && AUTOMOTIVE_ORGS.has(orgKey(incident.org)))
                || (largeRetail && LARGE_RETAIL_ORGS.has(orgKey(incident.org)))
              )) return false;
              return true;
            });
          }

          function currentSort'''
    ),
    audit,
    count=1,
    flags=re.S,
)
audit = audit.replace(
    '      .source-badge:hover{color:var(--text-primary)}.evidence-links{display:flex;gap:7px;flex-wrap:wrap;margin-top:5px;font-size:11.5px;color:var(--text-secondary)}\n',
    '      .source-badge:hover{color:var(--text-primary)}.evidence-links{display:flex;gap:7px;flex-wrap:wrap;margin-top:5px;font-size:11.5px;color:var(--text-secondary)}\n'
    '      .local-analysis{margin-top:9px;padding:9px 10px;border:1px solid var(--border);border-radius:8px;background:var(--plane);font-size:12.5px;font-weight:400;line-height:1.45}.local-analysis p{margin:6px 0 0}.local-score{display:inline-flex;align-items:center;padding:2px 7px;border:1px solid var(--border);border-radius:999px;font-weight:650}.local-analysis .evidence-links{margin-top:7px}\n',
)
local_renderer = dedent(
    '''\
      function renderLocalAnalysis(incident, enabled) {
        const local = incident.local;
        if (!enabled || !local) return "";
        const references = [...new Set((local.references || []).map(safeUrl).filter(Boolean))];
        const links = references.length
          ? `<div class="evidence-links"><span>Références :</span>${references.slice(0, 4).map((url, i) => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer" title="${esc(url)}">${esc(host(url))}${references.length > 1 ? ` ${i + 1}` : ""}</a>`).join("")}${references.length > 4 ? `<span>+${references.length - 4}</span>` : ""}</div>`
          : "";
        return `<div class="local-analysis"><span class="local-score">Score cyberattaque : ${esc(local.score)}/100</span><p><strong>Synthèse :</strong> ${esc(local.summary || "—")}</p>${links}</div>`;
      }

    '''
)
marker = "  function renderIncidentTable() {"
if marker not in audit:
    raise RuntimeError("renderIncidentTable absent")
audit = audit.replace(marker, local_renderer + marker, 1)
audit = audit.replace(
    "    tableObserver?.disconnect();\n    tbody.innerHTML = shown.map((incident) => `<tr>",
    "    const localOnly = $(\"#f-local\")?.getAttribute(\"aria-pressed\") === \"true\";\n    tableObserver?.disconnect();\n    tbody.innerHTML = shown.map((incident) => `<tr>",
    1,
)
audit = audit.replace(
    '<td data-label="Organisation" class="wrap-cell org-cell">${esc(incident.org || "Organisation inconnue")}</td>',
    '<td data-label="Organisation" class="wrap-cell org-cell">${esc(incident.org || "Organisation inconnue")}${renderLocalAnalysis(incident, localOnly)}</td>',
    1,
)
write("assets/dashboard-audit.js", audit)

# ---------------------------------------------------------------------------
# Tests Veille LLM / Local.
# ---------------------------------------------------------------------------
write(
    "tests/test_veillellm.py",
    dedent(
        '''\
        import json

        from cyberwatch import config, identity, site, sources, store
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


        def test_veille_llm_source_is_active_local_snapshot():
            spec = sources.by_id("VEILLE_LLM")
            assert spec is not None and spec.active
            assert spec.collector == "veillellm"
            assert spec.layer == config.LAYER_REGIONAL_WATCH
            assert spec.params["replace_snapshot"] is True
            assert spec.params["non_evidence_source"] is True
            assert spec.zone == "La Réunion / Mayotte"


        def test_veille_llm_imports_full_snapshot_and_rejects_weak_signals():
            spec = sources.by_id("VEILLE_LLM")
            with open(spec.params["path"], encoding="utf-8") as handle:
                raw = json.load(handle)
            result = get_collector(spec.collector).collect(
                None, spec, Window("2026-01-01", "2026-08-15")
            )
            assert result.resolve() == ("OK", 100)
            assert result.items_seen == raw["metadata"]["record_count"] == len(raw["incidents"])
            expected = [
                row for row in raw["incidents"]
                if int(row["score_cyberattaque"]) >= spec.params["min_score"]
                and row["date"] <= "2026-08-15"
            ]
            assert len(result.entries) == len(expected)
            assert all(entry.location in {config.LOC_REUNION, config.LOC_MAYOTTE} for entry in result.entries)


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


        def test_dashboard_payload_exposes_local_summary_score_and_references():
            items = store.load_items()
            incidents = store.load_incidents()
            analysis = site._local_analysis_by_incident(items)
            assert analysis
            payload = site.incidents_payload(incidents, analysis)
            local_rows = [row for row in payload if row.get("local")]
            assert local_rows
            assert all(0 <= row["local"]["score"] <= 100 for row in local_rows)
            assert all(row["local"]["summary"] for row in local_rows)
            assert all(row["local"]["references"] for row in local_rows)


        def test_dashboard_has_only_local_filter_for_local_watch():
            html = open("index.html", encoding="utf-8").read()
            legacy = open("assets/app-legacy.js", encoding="utf-8").read()
            audit = open("assets/dashboard-audit.js", encoding="utf-8").read()
            assert 'id="f-local"' in html
            assert '>Local</button>' in html
            assert 'f-veille-llm' not in html + legacy + audit
            assert 'f-presse-mahoraise' not in html + legacy + audit
            assert "incident.local" in legacy
            assert "incident.local" in audit
            assert "Score cyberattaque" in audit
            assert "Synthèse" in audit
        '''
    ),
)

# ---------------------------------------------------------------------------
# Documentation simplifiée.
# ---------------------------------------------------------------------------
write(
    "README.md",
    dedent(
        '''\
        # Cyberwatch V0

        Cyberwatch maintient un observatoire déterministe d'incidents cyber publiquement
        documentés en France et dans l'Océan Indien : **collecte → normalisation →
        qualification offline → déduplication → hashes → snapshot/dashboard**.

        **Dashboard : https://ya7o.github.io/Cyberwatch/**

        ## Sources actives

        Le pipeline actif est volontairement réduit à cinq sources :

        - FrenchBreaches
        - BonjourLaFuite
        - Cyberattaque.org
        - Ransomware.live
        - Veille LLM (`sources/veillellm/cyberattaques_reunion_mayotte_2026.json`)

        Veille LLM constitue la couverture locale analytique **La Réunion + Mayotte**.
        Le snapshot complet est relu à chaque MAJ ; seuls les dossiers dont le
        `score_cyberattaque >= 50` sont matérialisés. Les références documentaires du
        JSON restent visibles dans le filtre **Local**, mais Veille LLM ne compte pas
        comme une corroboration éditoriale supplémentaire lorsqu'un incident existe déjà
        dans une source directe.

        Les anciens collecteurs presse Mayotte (Kwezi, Mayotte Hebdo, Journal de Mayotte,
        Mayotte FM) ont été retirés : l'extraction automatique de victime dans la presse
        généraliste produisait des faux positifs. Leur corpus n'est plus conservé dans
        `ITEMS`.

        ## Dashboard

        Les actions rapides comprennent notamment **Local**. Lorsque ce filtre est actif,
        chaque incident affiche en plus :

        - le score cyberattaque du snapshot Veille LLM ;
        - la synthèse analytique ;
        - les URLs de référence du dossier.

        Ces éléments ne sont pas affichés hors du filtre Local afin de garder la vue
        générale compacte.

        ## Exploitation

        ```bash
        pip install -r requirements.txt
        python -m cyberwatch create
        python -m cyberwatch check
        python -m cyberwatch test-repeat
        python -m cyberwatch baseline   # facultatif
        python -m cyberwatch build-site
        ```

        Une base existante se met à jour avec :

        ```bash
        python -m cyberwatch maj
        ```

        La MAJ utilise une fenêtre glissante de 21 jours pour les sources réseau et relit
        toujours le snapshot Veille LLM complet afin d'intégrer les découvertes locales
        historiques tardives.

        ## Validation

        La CI obligatoire reste volontairement légère :

        - `pytest` ;
        - syntaxe JavaScript ;
        - `python -m cyberwatch test-repeat` ;
        - `python -m cyberwatch check --allow-uninitialized`.

        `REPLAY` et `test-repeat` sont offline et déterministes. Les audits spécialisés de
        qualité restent disponibles manuellement mais ne bloquent pas chaque push.

        ## Données

        - `data/items.csv` : items collectés ;
        - `data/incidents.csv` : incidents dédupliqués ;
        - `data/sources.csv` : référentiel des sources ;
        - `data/run_sources.csv` / `data/run_log.csv` : journal des collectes ;
        - `data/snapshot.json` : provenance et hashes du snapshot courant ;
        - `data/baseline.json` : référence locale facultative ;
        - `sources/veillellm/cyberattaques_reunion_mayotte_2026.json` : veille locale analytique.

        Le projet liste des incidents publiquement documentés ; il ne prétend pas recenser
        toutes les cyberattaques réelles.
        '''
    ),
)

method = read("METHODOLOGY.md")
method = re.sub(
    r"## Couverture locale Mayotte\n.*?\n## Initialisation et référence",
    dedent(
        '''\
        ## Couverture locale Réunion / Mayotte

        La couverture locale est fournie par le snapshot versionné **Veille LLM**
        (`sources/veillellm/cyberattaques_reunion_mayotte_2026.json`). Il est relu en
        totalité à chaque run afin qu'une découverte historique tardive soit intégrée
        sans dépendre de la fenêtre réseau de MAJ. Seuls les dossiers dont le score
        `score_cyberattaque >= 50` sont matérialisés dans `ITEMS`.

        Veille LLM est une source analytique : ses références documentaires sont exposées
        au dashboard mais ne gonflent jamais le compteur de corroboration éditoriale.
        Lorsqu'un incident est déjà couvert par une source directe, `Sources` reste fondé
        sur les sources directes. Lorsqu'il n'existe que dans Veille LLM, celle-ci reste
        la source unique afin qu'aucun incident ne soit dépourvu de provenance.

        Les collecteurs presse Mayotte du Lot 1 ont été retirés après observation de faux
        positifs d'extraction de victime dans des articles généralistes. La précision du
        corpus prime sur une couverture technique plus large mais bruitée.

        ## Initialisation et référence'''
    ),
    method,
    count=1,
    flags=re.S,
)
write("METHODOLOGY.md", method)

# Garde-fou : aucune logique UI/code Lot 1 ne doit rester.
for path in [
    "cyberwatch/sources.py",
    "cyberwatch/runner.py",
    "assets/app-legacy.js",
    "assets/dashboard-audit.js",
    "index.html",
    "README.md",
]:
    text = read(path)
    for source_id in {
        "KWEZI_NUMERIQUE", "MAYOTTE_HEBDO_NUMERIQUE", "JOURNAL_DE_MAYOTTE", "MAYOTTE_FM"
    }:
        if source_id in text:
            raise RuntimeError(f"{source_id} encore présent dans {path}")

print("Simplification Local appliquée.")
