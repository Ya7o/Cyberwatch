"""Régressions sur l'intégrité temporelle et la veille régionale publiée."""
from pathlib import Path

from cyberwatch.corpus_coverage import needs_backfill, summarize
from cyberwatch.site_window import latest_rows

ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _run(mode: str, start: str, end: str, status: str = "OK") -> dict:
    return {
        "Mode": mode,
        "Target_Start": start,
        "Target_End": end,
        "Overall_Status": status,
    }


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


def test_couverture_cumulee_ne_confond_pas_fenetre_maj_et_profondeur_du_corpus():
    runs = [
        _run("CREATE", "2026-01-01", "2026-08-28"),
        _run("MAJ", "2026-08-26", "2026-08-29"),
        _run("MAJ", "2026-08-27", "2026-08-30"),
    ]
    coverage = summarize(runs)
    assert coverage["start"] == "2026-01-01"
    assert coverage["end"] == "2026-08-30"
    assert coverage["days"] == 242
    assert needs_backfill(runs, "2026-01-01") is False


def test_rattrapage_maj_repare_un_create_partiel_sans_effacer_le_corpus():
    runs = [
        _run("CREATE", "2026-08-27", "2026-08-28"),
        _run("MAJ", "2026-01-01", "2026-08-30"),
    ]
    assert needs_backfill(runs[:1], "2026-01-01") is True
    assert summarize(runs)["start"] == "2026-01-01"
    assert needs_backfill(runs, "2026-01-01") is False


def test_rattrapage_broken_ne_fait_pas_croire_a_une_couverture_reparee():
    runs = [
        _run("CREATE", "2026-08-27", "2026-08-28"),
        _run("MAJ", "2026-01-01", "2026-08-30", "BROKEN"),
    ]
    assert summarize(runs)["start"] == "2026-08-27"
    assert needs_backfill(runs, "2026-01-01") is True


def test_un_nouveau_create_reinitialise_la_couverture_cumulee():
    runs = [
        _run("CREATE", "2026-01-01", "2026-08-20"),
        _run("MAJ", "2026-08-18", "2026-08-21"),
        _run("CREATE", "2026-08-27", "2026-08-28"),
    ]
    assert summarize(runs)["start"] == "2026-08-27"


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


def test_collecte_planifiee_est_active_et_bornee_par_l_epoque():
    workflow = _read(".github/workflows/collect.yml")
    assert 'cron: "0 7 * * *"' in workflow
    assert workflow.count("cron:") == 1
    assert "if: github.event_name == 'workflow_dispatch'" not in workflow
    assert "corpus_coverage.needs_backfill" not in workflow
    assert 'COLLECTION_EPOCH: "2026-08-28"' in workflow
    assert '--start "$COLLECTION_EPOCH"' in workflow
    assert 'echo "mode=maj"' in workflow
