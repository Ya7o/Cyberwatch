import csv,json,hashlib
from collections import Counter
from pathlib import Path
OUT=Path(__file__).resolve().parent
def read(p):return json.loads(p.read_text(encoding='utf-8-sig'))
stats={}
for run in ['run1','run2']:
 e=read(OUT/(run+'_evidence.json'));render=read(OUT/(run+'_render.json'));base=OUT/'snapshots'/run
 traces=read(base/'data/source_facts_ai_trace.json')
 for n,t in enumerate(traces):
  if run=='run2' and t.get('organisation') in ['Medikwestindies','CC Yvetot Normandie','Service national universel','SAD’S Interim']:
   context=t.get('context','');(OUT/(t['item_id']+'_context.txt')).write_text(context if isinstance(context,str) else json.dumps(context,ensure_ascii=False,indent=2))
   values=[]
   for o in t.get('response',{}).get('output',[]):
    for v in o.get('content',[]):
     if v.get('type')=='output_text':
      try:values.append(json.loads(v['text']))
      except ValueError:pass
   if values: (OUT/(t['item_id']+'_response_'+str(n)+'.json')).write_text(json.dumps(values,ensure_ascii=False,indent=2))
 sectors=[r['incident']['org'] for r in e if r['incident']['sector']=='Inconnu']
 loc=[r['incident']['org'] for r in e if r['incident']['location']=='Inconnu']
 types=[v for r in e for v in r['detail'].get('data_types',[])]
 fields=[v for r in e for v in r['detail'].get('fields',{}).values()]
 counts=[v for r in e for v in r['detail'].get('affected',[])]
 rej=Counter(k+':'+v for t in traces for k,v in t.get('rejections',{}).items())
 stats[run]={'incidents':len(e),'unknown_sectors':sectors,'unknown_locations':loc,'traces':len(traces),'traced_items':len({t['item_id'] for t in traces}),'traced_incidents':[r['incident']['org'] for r in e if r['traces']],'sector_reasons':{r['incident']['org']:r['incident']['sector_status'] for r in e if r['incident']['sector']=='Inconnu'},'types':len(types),'type_statuses':dict(Counter(v.get('status') for v in types)),'fields':len(fields),'field_statuses':dict(Counter(v.get('status') for v in fields)),'counts':len(counts),'count_statuses':dict(Counter(v.get('status') for v in counts)),'dropped_types':render['droppedCount'],'incidents_with_dropped_types':sum(bool(r['dropped_types']) for r in render['rendered'].values()),'empty_summaries':[r['incident']['org'] for r in e if not r['incident']['summary']],'rejections':dict(rej),'quality_alerts':dict(Counter(a['code'] for r in e for a in r['incident']['quality_alerts']))}
public={}
for p in ['incidents','facts','status']:
 path=OUT/('public_'+p+'.json')
 if path.exists():public[p]=read(path)==read(OUT/'snapshots/run2/assets/data'/(p+'.json'))
stats['public_matches_run2']=public
(OUT/'metrics.json').write_text(json.dumps(stats,ensure_ascii=False,indent=2)+'\n')
print(json.dumps(stats,ensure_ascii=False,indent=2))
