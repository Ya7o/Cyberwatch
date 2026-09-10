"""Read-only, offline probes for the latest collection (no LLM runtime)."""
import csv, json, hashlib, sys
from pathlib import Path
from dataclasses import asdict
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from cyberwatch.model import Item
from cyberwatch import dedup, duplicate_audit, dedup_ai, normalize, sector, threat_resolution
from cyberwatch.source_facts_ai import _deterministic_initial_access, _truncate_context, _full_context
from cyberwatch.collectors.base import RawEntry

def rows(name): return list(csv.DictReader((ROOT/'data'/f'{name}.csv').open()))
items=[Item.from_row(r) for r in rows('items')]
new=[i for i in items if i.Collected_As_Of.startswith('2026-09-10')]
facts={r['Item_ID']:r for r in rows('source_facts')}
queue=json.loads((ROOT/'data/source_facts_retry_queue.json').read_text())['entries']
cache=json.loads((ROOT/'data/source_facts_ai_cache.json').read_text())['entries']
output={'probes':[], 'candidates':[], 'published':{}, 'cached_reobserved':[]}
for obj in queue:
    iid=obj['item']['Item_ID']
    if iid not in {i.Item_ID for i in new}: continue
    entry=RawEntry(**obj['entry'])
    context=_full_context(entry)
    item=next(i for i in new if i.Item_ID==iid)
    fact=facts[iid]
    probe={'item_id':iid,'full_context_chars':len(context),'context_hash_matches':hashlib.sha256(context.encode()).hexdigest()==json.loads(fact['Source_Metadata_JSON'])['_source_facts_content_hash'],
        'truncation_needed_default':len(context)>10000,'sector_name_result':sector.classify_sector_name(item.Organisation_Raw),
        'deterministic_initial_access':_deterministic_initial_access(context),
        'resolved_threat':asdict(threat_resolution.resolve_component([item],{iid:[fact]})),
        'dedup_input':dedup_ai._item_payload(item,facts,'')}
    output['probes'].append(probe)
for c in duplicate_audit.find_daily_llm_candidates(new,items):
    output['candidates'].append({'left':c.left.Organisation_Raw,'right':c.right.Organisation_Raw,'left_id':c.left.Item_ID,'right_id':c.right.Item_ID,'days_apart':c.days_apart,'signals':asdict(c.signals),'decision':asdict(dedup.decide_merge(c.left,c.right))})
for phrase in ['Il serait donc prématuré de parler de ransomware ou de fuite de données.', 'Aucune fuite de données confirmée à ce stade']:
    output.setdefault('negation_probes',[]).append({'text':phrase,'result':normalize.classify_threat(phrase),'cleaned':normalize.threat_evidence_text(phrase)})
ids={r['Incident_ID'] for r in rows('incidents') if r['First_seen'].startswith('2026-09-10')}
for fn in ['incidents','facts']:
    data=json.loads((ROOT/'assets/data'/f'{fn}.json').read_text())
    output['published'][fn]=[r for r in data if r['id'] in ids] if isinstance(data,list) else {k:v for k,v in data.items() if k in ids}
for item in items:
    if item.Published_Date!='2026-09-09' or item.Item_ID in {i.Item_ID for i in new}: continue
    fact=facts.get(item.Item_ID,{})
    meta=json.loads(fact.get('Source_Metadata_JSON') or '{}')
    matching=[e for e in cache.values() if e.get('item_id')==item.Item_ID and e.get('content_hash')==meta.get('_source_facts_content_hash')]
    output['cached_reobserved'].append({'item_id':item.Item_ID,'organisation':item.Organisation_Raw,'source':item.Source_ID,'metadata':meta,'cache':matching})
out=Path(__file__).with_name('evidence.json')
out.write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({k:v for k,v in output.items() if k not in ('published','cached_reobserved')},ensure_ascii=False,indent=2))
for r in output['cached_reobserved']:
    print('CACHE',r['organisation'],r['source'],[{k:v for k,v in e.items() if k!='fields'} for e in r['cache']])
    for e in r['cache']:
        print('ACCEPTED',json.dumps({k:v for k,v in e['fields'].items() if v['status']=='accepted'},ensure_ascii=False))
for k,v in output['published']['facts'].items():
    print('PUBLISHED_FACT',k,json.dumps(v,ensure_ascii=False))
