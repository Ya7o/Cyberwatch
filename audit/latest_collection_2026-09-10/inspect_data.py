import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
def rows(name):
    return list(csv.DictReader((ROOT / 'data' / (name + '.csv')).open()))
def js(value):
    return json.dumps(value, ensure_ascii=False, indent=2)
run = json.loads((ROOT / 'data/snapshot.json').read_text())['Run_ID']
for name in ['run_log', 'production_metrics', 'run_sources']:
    print(name, js([r for r in rows(name) if r.get('Run_ID') == run]))
items = rows('items')
new = [r for r in items if r['Collected_As_Of'].startswith('2026-09-10')]
print('NEW', js(new))
ids = {r['Item_ID'] for r in new} | {x['item_id'] for x in json.loads((ROOT / 'data/source_facts_ai_trace.json').read_text())} | {'ITM-2d8408666ad4a2ab'}
for r in items:
    if r['Item_ID'] in ids:
        print('ITEM', js(r))
for r in rows('source_facts'):
    if r['Item_ID'] in ids:
        print('FACT', js(r))
for name in ['source_facts_ai_cache', 'source_facts_retry_queue']:
    obj = json.loads((ROOT / 'data' / (name + '.json')).read_text())
    print(name, str(obj)[:3500])
