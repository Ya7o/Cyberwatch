#!/usr/bin/env python3
# Refreshed after primary-source enrichment v7.
import json
from pathlib import Path
for stem in ('cyberattaque_org_2026','frenchbreaches_2026'):
    d=json.loads(Path(f'sources/veillellm/{stem}.json').read_text(encoding='utf-8'))
    rows=[x for x in d['incidents'] if x.get('secteur')=='Inconnu']
    print(f'=== {stem} UNKNOWN={len(rows)} ===')
    for x in rows:
        print('\t'.join([x.get('date',''),x.get('organisation',''),x.get('territoire',''),x.get('localisation',''),(x.get('sources') or [''])[0]]))
