from pathlib import Path

path = Path("tests/test_location_resolution.py")
text = path.read_text(encoding="utf-8")
old = '_live_item("BONJOURLAFUITE", "Société Mayotte Test")'
new = '_live_item("BONJOURLAFUITE", "Société Archipel Test")'
if old not in text:
    raise SystemExit("fixture BonjourLaFuite attendu introuvable")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
