#!/usr/bin/env python3
import csv,json,re
from pathlib import Path
import requests

OUT=Path('sources/veillellm')
STEMS=('cyberattaque_org_2026','frenchbreaches_2026')

# Reuse the exact French public-registry logic from v3 to distinguish a taxonomy gap
# from a legal-entity resolution failure. This pass writes a diagnostic only.
import deep_company_enrichment_v3 as v3

UNMAPPED={
 '01':'Agriculture','02':'Sylviculture','03':'Pêche','05':'Extraction','06':'Extraction','07':'Extraction','08':'Extraction','09':'Services extractifs',
 '55':'Hébergement','56':'Restauration','59':'Audiovisuel/cinéma','60':'Radio/télévision',
 '90':'Arts/création','91':'Bibliothèques/musées','92':'Jeux de hasard','93':'Sports/loisirs','94':'Associations','96':'Services personnels'
}

def registry_diag(org):
    try:
        r=requests.get('https://recherche-entreprises.api.gouv.fr/search',params={'q':org,'per_page':10},timeout=10)
        if r.status_code!=200:return ('registry_error','','','')
        res=r.json().get('results') or []
    except Exception:return ('registry_error','','','')
    target=v3.fold(org); exact=[]
    for c in res:
        if any(v3.fold(n)==target for n in v3.candidate_names(c)): exact.append(c)
    if not exact:return ('not_found','','','')
    sirens={str(c.get('siren','')) for c in exact if c.get('siren')}
    if len(sirens)!=1:return ('ambiguous','','','')
    c=next(c for c in exact if str(c.get('siren','')) in sirens)
    code=str(c.get('activite_principale') or '')
    mapped=v3.sector_from_naf(code)
    label=UNMAPPED.get(re.sub(r'\D','',code)[:2],'')
    return ('taxonomy_gap' if not mapped else 'mapped_but_missed',str(c.get('siren','')),code,label or mapped or '')

rows=[]
for stem in STEMS:
    d=json.loads((OUT/f'{stem}.json').read_text(encoding='utf-8'))
    for x in d['incidents']:
        if x.get('secteur')!='Inconnu':continue
        org=x.get('organisation','')
        status,siren,ape,label=registry_diag(org) if x.get('territoire') in ('France','La Réunion','Mayotte','Inconnu') else ('non_french_or_unknown','','','')
        rows.append({
          'corpus':stem,'date':x.get('date',''),'organisation':org,'territoire':x.get('territoire',''),'localisation':x.get('localisation',''),
          'registry_status':status,'siren':siren,'ape':ape,'activity_or_gap':label,'source':(x.get('sources') or [''])[0]
        })

p=OUT/'remaining_unknown_sectors_audit.csv'
with p.open('w',encoding='utf-8',newline='') as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0]) if rows else ['corpus']);w.writeheader();w.writerows(rows)
summary={}
for r in rows:
    summary[r['registry_status']]=summary.get(r['registry_status'],0)+1
(OUT/'remaining_unknown_sectors_audit.json').write_text(json.dumps({'count':len(rows),'summary':summary,'rows':rows},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print('TOTAL',len(rows),'SUMMARY',summary)
