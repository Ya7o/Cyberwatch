import json,sys
from pathlib import Path
OUT=Path(__file__).resolve().parent
e=json.loads((OUT/'run2_evidence.json').read_text())
for r in e:
 if not any(t.lower() in r['incident']['org'].lower() for t in sys.argv[1:]):continue
 print('\n',r['incident']['org'],r['incident']['id'],r['incident']['date'])
 for i in r['items']:print('ITEM',i)
 for f in r['source_facts']:
  meta=json.loads(f['Source_Metadata_JSON'] or '{}');print('METADATA',json.dumps({k:v for k,v in meta.items() if k not in ('rich_facts',)},ensure_ascii=False)[:4500])
 for a in r['detail']['affected']:print('COUNT',a)
 print('DEDUPE',r['dedup_log'])
