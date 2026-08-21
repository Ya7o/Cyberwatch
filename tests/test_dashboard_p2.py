from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_index_loads_p2_assets_after_legacy_runtime():
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    assert 'assets/p2.css' in html
    assert 'assets/p2.js' in html
    assert html.index('assets/app.js') < html.index('assets/p2.js')


def test_p2_runtime_keeps_static_progressive_enhancement_contract():
    js = (ROOT / "assets" / "p2.js").read_text(encoding="utf-8")
    assert 'assets/data/incidents.json' in js
    assert 'assets/data/status.json' in js
    assert 'document.documentElement.classList.add("p2-active")' in js
    assert 'history.replaceState' in js
    assert 'navigator.clipboard.writeText' in js
    assert 'showModal()' in js
    forbidden = ("React", "Vue", "WebSocket", "fetch('/api", 'fetch("/api')
    assert not any(token in js for token in forbidden)


def test_p2_exposes_required_product_views():
    js = (ROOT / "assets" / "p2.js").read_text(encoding="utf-8")
    required = (
        "Recherche transversale",
        "Couverture géographique",
        "Tendance récente",
        "openIncident",
        "openOrganisation",
        "mono-source",
        "corroboré",
        "aucun incident réel",
    )
    for token in required:
        assert token in js


def test_p2_css_hides_legacy_explorer_only_after_activation():
    css = (ROOT / "assets" / "p2.css").read_text(encoding="utf-8")
    assert ".p2-active .filters-toolbar" in css
    assert ".p2-active .incidents-card" in css
    assert "@media(max-width:760px)" in css
