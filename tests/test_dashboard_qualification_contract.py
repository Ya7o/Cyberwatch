from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_qualification_warning_is_routed_to_secondary_diagnostic():
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "assets" / "dashboard-v2.js").read_text(encoding="utf-8")
    assert "dashboard-qualification.js" not in html
    assert '?diagnostic=1#production-title' in html
    assert 'id="health-dialog"' in html
    alert = js[js.index("function renderIntegrityAlert"):js.index("function renderVeille")]
    assert "qualification" not in alert
    assert 'qualification.reasons || []' in js
