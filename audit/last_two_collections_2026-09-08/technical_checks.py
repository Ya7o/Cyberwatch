import json,sys,csv
from pathlib import Path
OUT=Path(__file__).resolve().parent; ROOT=OUT.parents[1];sys.path.insert(0,str(ROOT))
from cyberwatch import dedup,incident_dedup,store,org_identity,normalize,location_resolution
from cyberwatch.model import Item
read=lambda p:json.loads(p.read_text(encoding='utf-8-sig'))
e=read(OUT/'run2_evidence.json'); by={r['incident']['id']:r for r in e}
base=OUT/'snapshots/run2';items=store.load_items(base/'data/items.csv')
decisions=incident_dedup.decision_map(list(csv.DictReader((base/'data/incident_dedup_registry.csv').open())))
org_identity.reload_organisation_identity_registry(base/'data/organisation_identity_registry.csv')
pairs=[('INC-EEC788C594CA','INC-A11BA9A22689'),('INC-DC0BCFD579B8','INC-B44C794AB35B'),('INC-2C5CD2459F83','INC-45561E350283'),('INC-B7DBF665E661','INC-619638DA1C52'),('INC-DD17DC78C96C','INC-2C5CEAE9E3AC')]
result={'separations':[],'location_probes':{},'snapshot_deltas':{}}
for l,r in pairs:
 for a in by[l]['items']:
  for b in by[r]['items']:
   result['separations'].append({'incidents':[l,r],'items':[a['Item_ID'],b['Item_ID']],'reason':dedup.separation_reason(items,a['Item_ID'],b['Item_ID'],decisions)})
for v in ['Seine-Maritime','Allondans, Doubs','Mont-de-Marsan','Guadeloupe','Aveyron']:
 result['location_probes'][v]=normalize.classify_location(given=v)
for prev,run in [('before','run1'),('run1','run2')]:
 a={r['incident']['id']:r for r in read(OUT/(prev+'_evidence.json'))};b={r['incident']['id']:r for r in read(OUT/(run+'_evidence.json'))}
 result['snapshot_deltas'][run]={'changed_detail_ids':[k for k in b if k in a and a[k]['detail']!=b[k]['detail']], 'changed_incident_ids':[k for k in b if k in a and a[k]['incident']!=b[k]['incident']], 'added_ids':sorted(b.keys()-a.keys()),'removed_ids':sorted(a.keys()-b.keys())}
pub=OUT/'public_dashboard-v2.js'
result['renderer_matches_public']=pub.read_text(encoding='utf-8-sig').strip()==(ROOT/'assets/dashboard-v2.js').read_text().strip()
assert result['renderer_matches_public']
assert by['INC-61993D19E8E2']['detail']['fields']['data_volume']['value']=='5,79 To'
assert 'Berlin' in by['INC-61993D19E8E2']['detail']['fields']['data_volume']['evidence']
assert any(x['value']==150000 for x in by['INC-EE0E8F96C169']['detail']['affected'])
assert by['INC-995C9F7252C1']['source_facts'][0]['File_Count']=='250' and not by['INC-995C9F7252C1']['detail']['affected']
(OUT/'technical_checks.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');print(json.dumps(result,ensure_ascii=False,indent=2))
