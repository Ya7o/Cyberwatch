#!/usr/bin/env python3
"""Benchmark offline HEAD-only de la qualification Cyberattaque.org."""
from __future__ import annotations
import argparse, csv, hashlib, json, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cyberwatch import config, sources
from cyberwatch.collectors.base import RawEntry, SourceSpec
from cyberwatch.collectors.cyberattaque_org import is_negated_incident, is_obvious_multi, organisation_from_cyberattaque_entry
from cyberwatch.normalize import organisation_key

ARTICLES = ROOT / 'tests/fixtures/cyberattaque_org_articles_2026-08-14.json'

def golden():
    with tempfile.NamedTemporaryFile(suffix='.csv') as f:
        subprocess.run([sys.executable, str(ROOT/'scripts/materialize_cyberattaque_llm_reference.py'), '--output', f.name], cwd=ROOT, check=True, capture_output=True)
        return list(csv.DictReader(open(f.name, encoding='utf-8')))

def classify(entry, org):
    if is_negated_incident(entry.title, entry.summary, entry.content): return 'NEGATED'
    if is_obvious_multi(entry.title, entry.summary, entry.content): return 'MULTI'
    return 'DIRECT' if org else 'NO_VICTIM'

def run():
    payload=json.loads(ARTICLES.read_text(encoding='utf-8')); refs=golden()
    if payload.get('article_count') != 408 or len(payload['articles']) != 408 or len(refs) != 408: raise ValueError('408 articles/décisions requis')
    by_id={x['Source_Item_ID']:x for x in refs if x['Source_Item_ID']}; by_url={x['URL']:x for x in refs}
    rows=[]
    for raw in payload['articles']:
        e=RawEntry(**raw); ref=by_id.get(e.source_item_id) or by_url.get(e.url)
        if not ref: raise ValueError('article fixture absent du golden')
        org=organisation_from_cyberattaque_entry(e,{})
        mode=classify(e,org); match=organisation_key(org)==organisation_key(ref['LLM_Organisation'])
        category='MULTI' if mode=='MULTI' else 'NEGATED_OR_DISPUTED' if mode=='NEGATED' else 'SEMANTIC_DIFFERENCE_ACCEPTED' if not org else 'CANONICALISATION'
        rows.append({'Source_Item_ID':e.source_item_id,'Published_Date':e.published,'Title':e.title,'URL':e.url,'Golden_Organisation':ref['LLM_Organisation'],'Golden_Status':ref['LLM_Status'],'Golden_Confidence':ref['LLM_Confidence'],'Head_Organisation':org,'Head_Status':'SINGLE' if org else mode,'Resolution_Mode':mode,'Match':'MATCH' if match else 'DIFF','Diff_Classification':category})
    return sorted(rows,key=lambda r:(r['Published_Date'],r['Source_Item_ID'],r['URL']))

def write(rows,path):
    fields=list(rows[0]);
    with open(path,'w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,lineterminator='\n');w.writeheader();w.writerows(rows)
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',default='/tmp/cyberattaque_head.csv');p.add_argument('--check',action='store_true');p.add_argument('--max-high-confidence-diff',type=int,default=37,help='Régression maximale acceptée contre le golden versionné.');a=p.parse_args()
    rows=run(); h=write(rows,a.output); modes={m:sum(r['Resolution_Mode']==m for r in rows) for m in ('NEGATED','MULTI','DIRECT','NO_VICTIM','MISSING')}; exact=sum(r['Match']=='MATCH' for r in rows)
    high_diff=sum(r['Match']=='DIFF' and r['Golden_Confidence']=='HIGH' for r in rows)
    print(f'articles_total={len(rows)}');print(f'exact_match={exact}');print(f'diff={len(rows)-exact}');
    for k,v in modes.items(): print(f'{k.lower()}={v}')
    print('high_confidence_match='+str(sum(r['Match']=='MATCH' and r['Golden_Confidence']=='HIGH' for r in rows)));print('high_confidence_diff='+str(high_diff));print('medium_confidence_match='+str(sum(r['Match']=='MATCH' and r['Golden_Confidence']=='MEDIUM' for r in rows)));print('medium_confidence_diff='+str(sum(r['Match']=='DIFF' and r['Golden_Confidence']=='MEDIUM' for r in rows)));print('benchmark_hash='+h)
    if a.check:
        with tempfile.NamedTemporaryFile(suffix='.csv') as f:
            if h != write(run(),f.name): raise SystemExit('benchmark non déterministe')
        if high_diff > a.max_high_confidence_diff:
            raise SystemExit(f'quality regression: high-confidence differences {high_diff} > {a.max_high_confidence_diff}')
        print('check=PASS')
if __name__=='__main__': main()
