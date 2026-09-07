import json,csv,sys,itertools,copy
from pathlib import Path
from collections import Counter
p=Path(__file__).parent;root=p.parents[1];sys.path.insert(0,str(root))
from cyberwatch import store,dedup,duplicate_audit,dedup_ai,org_identity
from cyberwatch.sector_activity import activity_from_text,supported_activity
from cyberwatch.sector import classify_sector_activity
print('TRACE',Counter(x.get('status') for x in json.loads((root/'data/source_facts_ai_trace.json').read_text())))
for row in csv.DictReader((root/'data/run_sources.csv').open()):
 if row.get('Run_ID')=='RUN-20260906T085824':print('RUN_SOURCE',row)
remote=list(csv.DictReader((p/'remote/data/incidents.csv').open()))
served=json.loads((p/'served_incidents.json').read_text())
print('PRODUCTION_UNKNOWN',sum(x['Secteur']=='Inconnu' for x in remote),len(remote),'SERVED',Counter(x['sector'] for x in served))
rf={x['Item_ID']:x for x in csv.DictReader((p/'remote/data/source_facts.csv').open())}
rc=json.loads((p/'remote/data/source_facts_ai_cache.json').read_text())
for i in csv.DictReader((p/'remote/data/items.csv').open()):
 if any(n in i['Organisation_Raw'].lower() for n in ['accent','par’stores']):
  f=rf.get(i['Item_ID'],{});print('PROD_TARGET',i['Item_ID'],i['Organisation_Raw'],i['Sector'],{k:f.get(k) for k in ['Activity_Description','Activity_Sector_Match']})
  for e in rc.get('entries',{}).values():
   if e.get('item_id')==i['Item_ID']:print('PROD_CACHE',e.get('fields',{}).get('activity_description'),e.get('fields',{}).get('activity_sector_match'))
items=store.load_items(); facts={x['Item_ID']:x for x in store.load_source_facts()}
target_ids={'ITM-31ca81b910b22756','ITM-909b1b6129a81f63','ITM-827f9d9d0933d5cb','ITM-c471c7f9bb97a447'}
scope=[i for i in items if i.Collected_As_Of.startswith('2026-09-06')]
allc=duplicate_audit.find_daily_llm_candidates(scope,items)
print('DAILY_FULL',len(allc),[(c.left.Item_ID,c.right.Item_ID) for c in allc if c.left.Item_ID in target_ids and c.right.Item_ID in target_ids])
for c in allc:
 if not (c.left.Item_ID in target_ids and c.right.Item_ID in target_ids):continue
 decision=dedup_ai.DedupAiDecision(status='OK',same_organisation='SAME',same_incident='SAME',confidence=0.95,evidence='offline simulated evidence',reason='offline simulated decision')
 org=dedup_ai.validate_ai_dedup_decision(c,decision);inc=dedup_ai.validate_ai_incident_decision(c,decision)
 prev=org_identity.ORGANISATION_IDENTITY_REGISTRY
 try:
  org_identity.ORGANISATION_IDENTITY_REGISTRY={**prev,org['Alias_Key']:org['Canonical_Key']}
  merged=dedup.decide_merge(c.left,c.right,{inc['Pair_Key']:'SAME'})
  print('SIMULATED_LLM_APPLICATION',c.left.Organisation_Raw,c.right.Organisation_Raw,merged)
 finally:org_identity.ORGANISATION_IDENTITY_REGISTRY=prev
texts=[('Les Curistes','Une importante fuite de données attribuée à Les Curistes, plateforme française spécialisée dans les cures et stations thermales, est revendiquée sur un forum cybercriminel.'),('PassPass','Une fuite de données attribuée à Pass Pass, service de mobilité des Hauts-de-France, est revendiquée ce samedi 5 septembre 2026 sur un forum cybercriminel.'),('Accent Rouge','Accent Rouge commercialise du mobilier, des luminaires, des portes, des poignées et différents équipements destinés notamment aux architectes, décorateurs et particuliers.')]
for org,text in texts:print('TEXT_REPRO',org,activity_from_text(org,text),supported_activity(org,text,text),classify_sector_activity(text))
