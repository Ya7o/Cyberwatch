from pathlib import Path

path = Path("tests/test_backfill_unknowns.py")
text = path.read_text(encoding="utf-8")
old = '        org="Association 974",\n'
new = '        org="Association du département 974",\n'
if text.count(old) != 1:
    raise SystemExit(f"cas Association 974 attendu une fois, trouvé {text.count(old)}")
path.write_text(text.replace(old, new), encoding="utf-8")
