from pathlib import Path

path = Path("cyberwatch/source_facts_ai.py")
text = path.read_text(encoding="utf-8")
old = r"|exfiltr\\w*|"
new = r"|exfiltr\w*|"
if old not in text:
    raise SystemExit("escaped exfiltration marker missing")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
