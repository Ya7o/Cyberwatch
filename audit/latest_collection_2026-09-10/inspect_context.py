import csv, json, hashlib
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
queue = json.loads((ROOT/'data/source_facts_retry_queue.json').read_text())
facts = {r['Item_ID']: r for r in csv.DictReader((ROOT/'data/source_facts.csv').open())}
cache = json.loads((ROOT/'data/source_facts_ai_cache.json').read_text())['entries']
new_ids = {'ITM-0c085da888611a12', 'ITM-f2c9b54af4eae1da'}
for obj in queue['entries']:
    entry = obj['entry']
    print('QUEUE META', json.dumps({k:v for k,v in obj.items() if k not in ('entry','item')},ensure_ascii=False))
    print('ENTRY KEYS', list(entry))
    item = obj['item']; iid = item['Item_ID']
    context = '\n\n'.join(entry.get(k,'').strip() for k in ('title','summary','content') if entry.get(k,'').strip())
    print('CONTEXT', iid, len(context), hashlib.sha256(context.encode()).hexdigest())
    (OUT/(iid+'-context.txt')).write_text(context)
    if iid in new_ids:
        print(context)
    else:
        print('HEAD', context[:300], 'TAIL', context[-250:])
for iid in new_ids:
    matches = [e for e in cache.values() if e.get('item_id') == iid]
    print('NEW CACHE ENTRIES',iid,len(matches))
for r in csv.DictReader((ROOT/'data/incidents.csv').open()):
    if 'tampon' in r['Organisation'].lower(): print('INCIDENT',json.dumps(r,ensure_ascii=False))
for r in csv.DictReader((ROOT/'data/sector_resolution.csv').open()):
    if r.get('Item_ID') in new_ids: print('SECTOR',json.dumps(r,ensure_ascii=False))
for fn in ['assets/data/incidents.json','assets/data/facts.json']:
    data=json.loads((ROOT/fn).read_text())
    print('ASSET SHAPE',fn,type(data).__name__,list(data)[:2] if isinstance(data,dict) else list(data[0])[:50])
