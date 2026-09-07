"""Régressions sur l'intégrité temporelle et la veille régionale publiée."""
from pathlib import Path

from cyberwatch.site_window import latest_rows

ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_latest_rows_est_ancre_sur_le_run_et_pas_sur_le_dernier_incident():
    rows = [
        {"id": "old", "date": "2026-07-31"},
        {"id": "edge", "date": "2026-08-01"},
        {"id": "new", "date": "2026-08-30"},
        {"id": "future", "date": "2026-08-31"},
    ]
    assert [row["id"] for row in latest_rows(rows, "2026-08-30T08:00:00+04:00")] == [
        "new",
        "edge",
    ]


def test_latest_rows_garde_un_repli_compatible_sans_date_de_run():
    rows = [
        {"id": "a", "date": "2026-01-01"},
        {"id": "b", "date": "2026-01-30"},
    ]
    assert [row["id"] for row in latest_rows(rows, "")] == ["b", "a"]


def test_site_public_passe_explicitement_la_date_du_run_a_la_fenetre():
    site = _read("cyberwatch/site.py")
    assert "site_window.latest_rows(" in site
    assert 'state.get("run", {}).get("as_of", "")' in site
    assert "_legacy._latest_payload(payload)" not in site


def test_garde_integrite_est_charge_apres_le_runtime_principal():
    html = _read("index.html")
    main = 'src="assets/dashboard-v2.js'
    guard = 'src="assets/dashboard-integrity.js'
    assert main in html and guard in html
    assert html.index(main) < html.index(guard)


def test_garde_integrite_utilise_la_couverture_cumulee_et_separe_les_candidates():
    js = _read("assets/dashboard-integrity.js")
    assert '=== "ACCEPTED"' in js
    assert '=== "CANDIDATE"' in js
    assert "Aucun incident cyber retenu" in js
    assert "signal non confirmé" in js
    assert "incident-card" in js
    assert "data/run_log.csv" in js
    assert "lastCreate" in js
    assert "La couverture cumulée du corpus principal" in js
    assert "Target_Start" in js and "Target_End" in js


def test_collecte_planifiee_est_active_et_quotidienne():
    workflow = _read(".github/workflows/collect.yml")
    assert 'cron: "0 7 * * *"' in workflow
    assert workflow.count("cron:") == 1
    assert "if: github.event_name == 'workflow_dispatch'" not in workflow
    assert "corpus_coverage.needs_backfill" not in workflow
    assert "COLLECTION_EPOCH" not in workflow
    assert "python -m cyberwatch maj" in workflow
    assert "create" not in workflow
