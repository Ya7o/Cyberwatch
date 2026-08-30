from pathlib import Path

path = Path(__file__).with_name("dev_apply_organisation_reference.py")
text = path.read_text(encoding="utf-8")
start_marker = '''replace_once(\n    "cyberwatch/organisation_sector_llm.py",\n    "La taxonomie n'est pas exhaustive : n'oblige jamais une activité sociale, "'''
end_marker = '''\ncache_helper_anchor = '''
start = text.find(start_marker)
end = text.find(end_marker, start)
if start < 0 or end < 0:
    raise SystemExit("prompt migration block not found")
replacement = '''replace_once(\n    "cyberwatch/organisation_sector_llm.py",\n    '    "La taxonomie n\\'est pas exhaustive : n\\'oblige jamais une activité sociale, "\\n'\n    '    "caritative ou associative à entrer dans \\'Services aux entreprises\\', qui "\\n'\n    '    "désigne exclusivement des prestations B2B. Exemple : une banque alimentaire "\\n'\n    '    "qui fournit de l\\'aide alimentaire reste Inconnu dans cette taxonomie. "\\n',\n    '    "La taxonomie contient désormais Association / Syndicat pour une nature syndicale ou professionnelle explicitement établie. "\\n'\n    '    "N\\'utilise jamais Services aux entreprises comme catégorie par défaut pour une association, un syndicat ou une structure caritative ; ce secteur désigne exclusivement des prestations B2B. "\\n',\n)\n'''
path.write_text(text[:start] + replacement + text[end:], encoding="utf-8")
print("migration script hardened")
