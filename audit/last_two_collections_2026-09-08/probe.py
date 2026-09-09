import json,sys
from pathlib import Path
OUT=Path(__file__).resolve().parent
name=sys.argv[1] if len(sys.argv)>1 else 'run2'
e=json.loads((OUT/(name+'_evidence.json')).read_text())
terms=sys.argv[2:]
for r in e:
    if terms and not any(t.lower() in r['incident']['org'].lower() for t in terms):continue
    print('\nINCIDENT',json.dumps(r['incident'],ensure_ascii=False))
    print('DETAIL',json.dumps(r['detail'],ensure_ascii=False))
    print('SECTOR',json.dumps(r['sector_log'],ensure_ascii=False))
    print('TRACES',json.dumps(r['traces'],ensure_ascii=False))
    for f in r['source_facts']:
        print('SOURCE_FACT',json.dumps({k:v for k,v in f.items() if k!='Source_Metadata_JSON' and v},ensure_ascii=False))
        meta=json.loads(f.get('Source_Metadata_JSON') or '{}')
        print('META',json.dumps(meta,ensure_ascii=False)[:1800])
