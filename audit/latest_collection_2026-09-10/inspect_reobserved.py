import csv,json
from pathlib import Path
root=Path(__file__).resolve().parents[2]
facts={r['Item_ID']:r for r in csv.DictReader((root/'data/source_facts.csv').open())}
out=json.loads(Path(__file__).with_name('evidence.json').read_text())
published=json.loads((root/'assets/data/facts.json').read_text())
incidents=list(csv.DictReader((root/'data/incidents.csv').open()))
for obj in out['cached_reobserved']:
    f=facts[obj['item_id']]
    print(obj['organisation'],obj['source'],{k:f[k] for k in ['Summary','Impact','Third_Party','Initial_Access','Attack_Flow_JSON']})
    print('CORRECTION',obj['metadata'].get('editorial_correction'))
for r in incidents:
    if r['Organisation'] in ('Citadium','Printemps'):
        print('FINAL',r['Organisation'],r['Incident_ID'],json.dumps(published[r['Incident_ID']]['fields'],ensure_ascii=False))
for r in csv.DictReader((root/'data/sources.csv').open()):
    if r.get('Source_ID') in ('FRENCHBREACHES','CYBERATTAQUE_ORG'): print('SPEC',r)
