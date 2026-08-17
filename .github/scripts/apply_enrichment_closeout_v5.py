from pathlib import Path

path = Path("cyberwatch/source_facts_ai.py")
text = path.read_text(encoding="utf-8")
old = "        if not _ATTACK_ACTION_RE.search(combined):\n            continue\n"
new = "        if not _ATTACK_ACTION_RE.search(combined) and \"exfiltr\" not in searchable(combined):\n            continue\n"
if old not in text:
    raise SystemExit("attack-action guard missing")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
