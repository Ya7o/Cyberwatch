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


def test_garde_integrite_ne_promeut_jamais_un_candidate_en_incident():
    js = _read("assets/dashboard-integrity.js")
    assert '=== "ACCEPTED"' in js
    assert '=== "CANDIDATE"' in js
    assert "Aucun incident cyber confirmé" in js
    assert "signal non confirmé" in js
    assert "incident-card" in js
    assert "Le corpus principal publié couvre" in js
    assert "target_start" in js and "target_end" in js
