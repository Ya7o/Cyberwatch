#!/usr/bin/env python3
import csv,json
from pathlib import Path

OUT=Path('sources/veillellm')
COLS=['date','organisation','territoire','localisation','secteur','type_menace','acteur','statut','score_cyberattaque','impact_connu','source_urls','synthese','evolution']

FIXES={
 'github':{
   'secteur':'Numérique / Technologie','territoire':'États-Unis','localisation':'San Francisco, Californie',
   'sources':['https://github.com/about','https://www.pappers.fr/entreprise/github-inc-800813156']},
 'productly.app':{
   'secteur':'Numérique / Technologie','sources':['https://productly.app/']},
 'apps.education.fr':{
   'secteur':'Éducation / Formation','territoire':'France','localisation':'France',
   'sources':['https://projet.apps.education.fr/','https://projet.apps.education.fr/mentions-legales/']},
 'easy cash':{
   'secteur':'Commerce / Distribution','territoire':'France','sources':['https://www.easycash.fr/']},
 'rituals':{
   'secteur':'Commerce / Distribution','territoire':'France',
   'sources':['https://www.rituals.com/fr-fr/stores','https://annuaire-entreprises.data.gouv.fr/entreprise/804544674']},
 'calendridel':{
   'secteur':'Numérique / Technologie','territoire':'France','sources':['https://www.calendridel.fr/']},
 'mediavacances':{
   'secteur':'Numérique / Technologie','territoire':'France','localisation':'Lambersart, Hauts-de-France',
   'sources':['https://www.mediavacances.com/company.php','https://www.mediavacances.com/who.php']},
 'clcv':{
   'territoire':'France','localisation':'Montrouge, Île-de-France',
   'sources':['https://www.clcv.org/','https://annuaire-entreprises.data.gouv.fr/entreprise/784244139']}
}

def key(s): return str(s or '').strip().casefold()

def run(stem):
    jp=OUT/f'{stem}.json'; cp=OUT/f'{stem}.csv'
    data=json.loads(jp.read_text(encoding='utf-8'))
    resolved=0; corrected=0; applied=[]
    before=sum(x.get('secteur')=='Inconnu' for x in data['incidents'])
    for x in data['incidents']:
        k=key(x.get('organisation'))
        fix=FIXES.get(k)
        if not fix: continue
        old_sector=x.get('secteur')
        changed=False
        for field in ('secteur','territoire','localisation'):
            if field in fix and x.get(field)!=fix[field]:
                x[field]=fix[field]; changed=True
        if fix.get('sources'):
            old=list(x.get('sources') or [])
            new=list(dict.fromkeys(old+fix['sources']))
            if new!=old: x['sources']=new; changed=True
        if changed:
            applied.append(x.get('organisation'))
            if old_sector=='Inconnu' and x.get('secteur')!='Inconnu': resolved+=1
            else: corrected+=1
            if x.get('evolution')!='nouveau': x['evolution']='enrichi'
    after=sum(x.get('secteur')=='Inconnu' for x in data['incidents'])
    data['metadata']['company_research_v6']={
      'before_sector_unknown':before,'resolved_sector_unknown':resolved,'remaining_sector_unknown':after,
      'other_data_corrections':corrected,'applied_to':applied,
      'method':'targeted manual verification from official company/service websites, official French company register and explicit legal/company pages',
      'evidence_policy':'only high-confidence residual cases; evidence URLs retained in incident sources'
    }
    jp.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    with cp.open('w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=COLS);w.writeheader()
        for x in data['incidents']:
            r={k:x.get(k,'') for k in COLS if k!='source_urls'}
            r['source_urls']=' | '.join(x.get('sources') or [])
            w.writerow(r)
    print(stem,'V6 BEFORE',before,'RESOLVED',resolved,'REMAINING',after,'CORRECTED',corrected,'APPLIED',applied,flush=True)

for stem in ('cyberattaque_org_2026','frenchbreaches_2026'):
    run(stem)
