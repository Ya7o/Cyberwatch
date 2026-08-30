from pathlib import Path

path = Path("cyberwatch/source_facts_ai.py")
text = path.read_text(encoding="utf-8")
old = '''            if sf._activity_evidence_matches_organisation(organisation, fact["evidence"]):\n                result["activity_description"] = fact\n'''
new = '''            if not organisation or sf._activity_evidence_matches_organisation(organisation, fact["evidence"]):\n                result["activity_description"] = fact\n'''
if old not in text:
    raise SystemExit("activity validation anchor not found")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
print("post-migration compatibility applied")
