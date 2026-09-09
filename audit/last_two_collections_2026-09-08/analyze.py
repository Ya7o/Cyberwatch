import csv,json,sys,hashlib
from pathlib import Path
from collections import Counter
ROOT=Path(__file__).resolve().parents[2]; OUT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from cyberwatch import store,site,org_identity
def load(base,p):
    path=base/p
    return list(csv.DictReader(path.open(encoding='utf-8-sig'))) if p.endswith('.csv') else json.loads(path.read_text())
def dump(p,v):p.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n')
originals={k:v for k,v in vars(store).items() if isinstance(v,Path)}
for name in ['before','run1','run2']:
    base=OUT/'snapshots'/name
    for k,v in originals.items():
        try: relative=v.relative_to(ROOT)
        except ValueError:continue
        setattr(store,k,base/relative)
    org_identity.reload_organisation_identity_registry(base/'data/organisation_identity_registry.csv')
    items=store.load_items(); rows=store.load_source_facts()
    comps=site._components_with_stable_incident_ids(items)
    raw=site._source_facts_by_incident(items,rows)
    incidents=load(base,'assets/data/incidents.json'); facts=load(base,'assets/data/facts.json')
    recomputed=site._resolved_details(incidents,raw)
    fi={r['Item_ID']:r for r in rows}; it={i.Item_ID:i for i in items}
    tr=load(base,'data/source_facts_ai_trace.json'); queue=load(base,'data/source_facts_retry_queue.json')['entries']
    sr=load(base,'data/sector_resolution.csv')
    enriched=[]
    for inc in incidents:
        iid=inc['id']; component=next((c for c,i in comps if i==iid),[]); ids={i.Item_ID for i in component}
        record={'incident':inc,'detail':facts.get(iid),'raw_facts':raw.get(iid),'items':[i.to_row() for i in component], 'source_facts':[fi[i.Item_ID] for i in component if i.Item_ID in fi], 'sector_log':[r for r in sr if r['Item_ID'] in ids], 'traces':[{'index':n,'item_id':t.get('item_id'),'status':t.get('status'),'requested_fields':t.get('requested_fields'),'normalized':t.get('normalized'),'rejections':t.get('rejections')} for n,t in enumerate(tr) if t.get('item_id') in ids], 'pending':[{'item_id':q['item']['Item_ID'],'fields':q['pending_fields'],'reason':q['reason'],'attempts':q['attempts']} for q in queue if q['item']['Item_ID'] in ids]}
        if name!='before':
            review=load(base,'data/dedup_review_latest.json')
            record['dedup_log']=[{**p,'left_org':it[p['left']].Organisation_Raw,'right_org':it[p['right']].Organisation_Raw} for p in review['pairs'] if p['left'] in ids or p['right'] in ids]
        enriched.append(record)
    dump(OUT/(name+'_evidence.json'),enriched)
    print(name,'recomputed differences', [i for i in facts if facts[i]!=recomputed.get(i)],'all components',len(comps))
    if name=='before':continue
    print('TRACE STATUSES',dict(Counter(t.get('status') for t in tr)))
    print('PENDING',[(it[q['item']['Item_ID']].Organisation_Raw,q['pending_fields'],q['reason'],q['attempts']) for q in queue])
    print('DEDUPE',[(it[p['left']].Organisation_Raw,it[p['right']].Organisation_Raw,p['status'],p['same_organisation'],p['same_incident'],p['confidence']) for p in review['pairs']])
    for r in enriched:
        i=r['incident'];d=r['detail'];print(i['id'],i['date'],i['org'],'|',i['sector'],i['threat'],i['location'],'|',i['threat_status']['status'],'| fields',','.join(d.get('fields',{})), '|',[(a.get('value'),a.get('unit'),a.get('status')) for a in d.get('affected',[])], '| data',[(a.get('value'),a.get('status')) for a in d.get('data_types',[])], '| traces',len(r['traces']))
