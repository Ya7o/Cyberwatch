#!/usr/bin/env python3
import csv,json,re,unicodedata
from pathlib import Path

OUT=Path('sources/veillellm')
COLS=['date','organisation','territoire','localisation','secteur','type_menace','acteur','statut','score_cyberattaque','impact_connu','source_urls','synthese','evolution']

def norm(s):
    s=str(s or '').replace('’',' ').replace("'",' ')
    s=unicodedata.normalize('NFKD',s).encode('ascii','ignore').decode().casefold()
    return re.sub(r'[^a-z0-9]+',' ',s).strip()

def f(sec,urls,territory=None,location=None):
    d={'secteur':sec,'sources':urls if isinstance(urls,list) else [urls]}
    if territory:d['territoire']=territory
    if location:d['localisation']=location
    return d

FIX={
 'bloctel':f('Administration / Collectivité',['https://www.bloctel.gouv.fr/CGU','https://www.bloctel.gouv.fr/mentions-legales'],'France','France'),
 'vaucluse provence attractivite':f('Services aux entreprises',['https://vaucluseprovence-attractivite.com/qui-sommes-nous/nos-missions/invest/','https://vaucluseprovence-attractivite.com/qui-sommes-nous/nos-missions/'],'France','Vaucluse, Provence-Alpes-Côte d’Azur'),
 'monservicederemplacement fr':f('Services aux entreprises',['https://servicederemplacement.fr/se-faire-remplacer'],'France','France'),
 'service de remplacement agricole':f('Services aux entreprises',['https://servicederemplacement.fr/se-faire-remplacer'],'France','France'),
 'adn tourisme':f('Services aux entreprises',['https://www.adn-tourisme.fr/services/','https://www.adn-tourisme.fr/qui-sommes-nous/missions/'],'France','Paris, Île-de-France'),
 'yggtorrent':f('Numérique / Technologie',['https://www.yggtorrent.support/','https://frenchbreaches.com/blog/cyberattaques-en-70-jours-commerce-sport-et-administrations-dans-le-viseur-des-hackers']),
 'breach forums':f('Numérique / Technologie',['https://frenchbreaches.com/blog/cyberattaques-en-70-jours-commerce-sport-et-administrations-dans-le-viseur-des-hackers']),
 'sos 33 bordeaux':f('Santé',['https://www.sosmedecins-bordeaux.com/','https://www.sosmedecins-bordeaux.com/mentions-legales'],'France','Bordeaux, Nouvelle-Aquitaine'),
 'airclaim':f('Finance / Assurance',['https://airclaim.com/fr/','https://airclaim.com/fr/terms-conditions/','https://frenchbreaches.com/blog/cyberattaques-en-70-jours-commerce-sport-et-administrations-dans-le-viseur-des-hackers']),
}

def run(stem):
    jp=OUT/f'{stem}.json';cp=OUT/f'{stem}.csv';d=json.loads(jp.read_text(encoding='utf-8'))
    before=sum(x.get('secteur')=='Inconnu' for x in d['incidents']);resolved=0;corrected=0;applied=[]
    for x in d['incidents']:
        q=FIX.get(norm(x.get('organisation')))
        if not q:continue
        old=x.get('secteur');changed=False
        for fld in ('secteur','territoire','localisation'):
            if fld in q and x.get(fld)!=q[fld]:x[fld]=q[fld];changed=True
        src=list(x.get('sources') or []);ns=list(dict.fromkeys(src+q.get('sources',[])))
        if ns!=src:x['sources']=ns;changed=True
        if changed:
            applied.append(x.get('organisation'))
            if old=='Inconnu' and x.get('secteur')!='Inconnu':resolved+=1
            else:corrected+=1
            if x.get('evolution')!='nouveau':x['evolution']='enrichi'
    after=sum(x.get('secteur')=='Inconnu' for x in d['incidents'])
    d['metadata']['company_research_v9']={'before_sector_unknown':before,'resolved_sector_unknown':resolved,'remaining_sector_unknown':after,'other_data_corrections':corrected,'applied_to':applied,'method':'final defensible residuals: public-service mission, professional/B2B service function, official medical service, and explicitly digital platform activity','evidence_policy':'remaining Inconnu values are retained when activity is outside the canonical taxonomy or identity/activity is still insufficiently evidenced'}
    jp.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    with cp.open('w',encoding='utf-8',newline='') as fh:
        w=csv.DictWriter(fh,fieldnames=COLS);w.writeheader()
        for x in d['incidents']:
            r={c:x.get(c,'') for c in COLS if c!='source_urls'};r['source_urls']=' | '.join(x.get('sources') or []);w.writerow(r)
    print(stem,'V9 BEFORE',before,'RESOLVED',resolved,'REMAINING',after,'CORRECTED',corrected,'APPLIED',applied,flush=True)
for stem in ('cyberattaque_org_2026','frenchbreaches_2026'):run(stem)
