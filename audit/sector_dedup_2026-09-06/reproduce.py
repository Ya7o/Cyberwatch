import csv,json,sys,itertools
from pathlib import Path
from collections import Counter
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from cyberwatch import store,sector_resolution,sector_activity,enrichment,dedup,duplicate_audit
from cyberwatch.normalize import searchable
items=store.load_items(); facts=store.load_source_facts(); incidents=store.load_incidents()
byfact={r['Item_ID']:r for r in facts}
bydecision={r['Item_ID']:r for r in store.load_sector_resolution()}
terms=['aveyron','curistes','accent rouge','jouvet','maison pour tous','pass','repar','youfid']
target=[i for i in items if any(t in searchable(i.Organisation_Raw) for t in terms)]
report={'snapshot':json.loads((ROOT/'data/snapshot.json').read_text()),'counts':{'items':len(items),'incidents':len(incidents),'unknown_incidents':sum(i.Secteur=='Inconnu' for i in incidents)},'targets':[],'pairs':[]}
for i in target:
 f=byfact.get(i.Item_ID,{})
 entry={'item':i.to_row(),'facts':f,'decision':bydecision.get(i.Item_ID),'resolved_now':sector_resolution.resolve_item(i,f,enrichment.load_reference()).__dict__}
 report['targets'].append(entry)
 print(json.dumps({k:v for k,v in entry.items() if k!='facts'},ensure_ascii=False))
 print('FACTS',json.dumps({k:v for k,v in f.items() if v and (k.startswith('Activity') or k in ['Evidence_JSON','Source_Metadata_JSON','Victim_Website','Source_Sector_Raw'])},ensure_ascii=False))
for a,b in itertools.combinations(target,2):
 if not (('pass' in searchable(a.Organisation_Raw) and 'pass' in searchable(b.Organisation_Raw)) or ('repar' in searchable(a.Organisation_Raw) and 'repar' in searchable(b.Organisation_Raw))):continue
 decision=dedup.decide_merge(a,b)
 pair={'left':a.Item_ID,'right':b.Item_ID,'names':[a.Organisation_Raw,b.Organisation_Raw],'deterministic':decision.__dict__,'signals':duplicate_audit.compute_candidate_signals(a,b).__dict__,'daily_candidates':len(duplicate_audit.find_daily_llm_candidates([a],[a,b]))}
 report['pairs'].append(pair);print('PAIR',json.dumps(pair,ensure_ascii=False))
(ROOT/'audit/sector_dedup_2026-09-06/local_evidence.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
print('COUNTS',report['counts'])
