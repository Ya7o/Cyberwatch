from pathlib import Path
import re


def replace_func(text, name, new_body):
    pattern = re.compile(rf"^def {re.escape(name)}\(.*?(?=^def |\Z)", re.M | re.S)
    match = pattern.search(text)
    if not match:
        raise SystemExit(f"function missing: {name}")
    return text[:match.start()] + new_body.rstrip() + "\n\n" + text[match.end():]


path = Path("cyberwatch/source_facts_ai.py")
text = path.read_text(encoding="utf-8")
old = 'r"serait|aurait|auraient|susceptible(?:s)?|non\\s+confirm[ée]|sans\\s+confirmation|reste\\s+inconnu)\\b",'
new = 'r"serait|agirait|aurait|auraient|susceptible(?:s)?|non\\s+confirm[ée]|sans\\s+confirmation|reste\\s+inconnu)\\b",'
if old not in text:
    raise SystemExit("hypothetical marker missing")
text = text.replace(old, new, 1)
text = replace_func(text, "_fields_needed", '''def _fields_needed(item: Item, entry: RawEntry, seed: dict | None = None) -> set[str]:
    requested = _legacy_fields_needed(item, entry, seed)
    if not _has_semantic_context(entry):
        return requested
    requested.update({"summary", "initial_access", "attack_flow"})
    if not (seed or {}).get("impact"):
        requested.add("impact")
    return requested
''')
path.write_text(text, encoding="utf-8")

path = Path("cyberwatch/source_facts.py")
text = path.read_text(encoding="utf-8")
old = '        previous = by_id.get(item_id)\n        by_id[item_id] = merge_row(previous, row) if previous else dict(row)\n'
new = '        previous = by_id.get(item_id)\n        by_id[item_id] = merge_row(previous or {}, row)\n'
if old not in text:
    raise SystemExit("merge marker missing")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
