from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_qualification_warning_is_routed_to_production_reliability():
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "assets" / "dashboard-qualification.js").read_text(encoding="utf-8")

    assert "assets/dashboard-qualification.js" in html
    assert html.index("assets/dashboard-v2.js") < html.index("assets/dashboard-qualification.js")
    assert '?vue=analyse#production-title' in html

    assert 'document.querySelector("#data-alert")' in js
    assert 'document.querySelector("#production-metrics")' in js
    assert 'qualification?.state !== "PARTIAL"' in js
    assert "qualification?.reasons" in js
    assert 'strong.textContent = "Couverture partielle."' in js
    assert "renderQualificationInProduction" in js
