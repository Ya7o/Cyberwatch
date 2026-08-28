#!/usr/bin/env python3
import csv,json,re,unicodedata
from pathlib import Path

OUT=Path('sources/veillellm')
COLS=['date','organisation','territoire','localisation','secteur','type_menace','acteur','statut','score_cyberattaque','impact_connu','source_urls','synthese','evolution']

def norm(s):
    # Critical: apostrophes separate lexical tokens (d’Indre -> d indre), they must not be silently removed.
    s=str(s or '').replace('’',' ').replace("'",' ')
    s=unicodedata.normalize('NFKD',s).encode('ascii','ignore').decode().casefold()
    return re.sub(r'[^a-z0-9]+',' ',s).strip()

def fix(sector, sources, territory=None, location=None):
    d={'secteur':sector,'sources':sources if isinstance(sources,list) else [sources]}
    if territory is not None:d['territoire']=territory
    if location is not None:d['localisation']=location
    return d

FIX={
# Cyberattaque.org residuals
'eva gg':fix('Sport',['https://www.eva.gg/','https://www.eva.gg/fr-FR/franchise']),
'hpa guide':fix('Numérique / Technologie',['https://www.hpa-guide.fr/mentions-legales','https://www.hpa-guide.fr/']),
'groupe cga':fix('Construction / BTP',['https://annuaire-entreprises.data.gouv.fr/entreprise/cga-gestion-479056897']),
'ademi':fix('Commerce / Distribution',['https://www.ademi-pesage.com/']),
'vranken pommery':fix('Industrie / Manufacture',['https://www.vrankenpommery.com/']),
# FrenchBreaches residuals confirmed by source-native metadata + actual victim activity
'evy':fix('Finance / Assurance',['https://www.evy.eu/fr','https://www.evy.eu/fr/legal-notice'],'France','Paris, Île-de-France'),
'heypulse':fix('Numérique / Technologie',['https://www.heypulse.fr/'],'France','France'),
'flymoove moove':fix('Numérique / Technologie',['https://www.flymoove.com/','https://www.flymoove.com/conditions-generales-de-vente'],'France','Paris, Île-de-France'),
'the burning descent':fix('Numérique / Technologie',['https://store.steampowered.com/app/1961460/The_Burning_Descent/']),
'batigam':fix('Construction / BTP',['https://frenchbreaches.com/alertes/batigam-mqxlcx6bsh0ei7abtc8']),
'papa france':fix('Commerce / Distribution',['https://www.papa-france.fr/']),
'sapeurs pompiers d indre et loire':fix('Administration / Collectivité',['https://www.sdis37.fr/'],'France','Indre-et-Loire'),
'ankama':fix('Numérique / Technologie',['https://www.ankama.com/fr/groupe','https://jobs.ankama.com/']),
'medoucine':fix('Numérique / Technologie',['https://www.medoucine.com/','https://www.medoucine.com/mentions-legales']),
'vivaticket tickeasy':fix('Numérique / Technologie',['https://www.vivaticket.com/','https://annuaire-entreprises.data.gouv.fr/entreprise/vivaticket-439186636']),
'be bunk':fix('Finance / Assurance',['https://www.be-bunk.com/','https://www.be-bunk.com/mentions-legales']),
'demande de logement':fix('Administration / Collectivité',['https://www.service-public.fr/particuliers/vosdroits/R34754'],'France','France'),
'espace cse':fix('Services aux entreprises',['https://www.espace-cse.fr/']),
'canada goose':fix('Industrie / Manufacture',['https://www.canadagoose.com/ca/en/our-history.html'],'Canada','Canada'),
'aikan':fix('Finance / Assurance',['https://www.aikan.io/','https://www.aikan.io/mentions-legales']),
'powerlab':fix('Commerce / Distribution',['https://www.powerlab.fr/','https://annuaire-entreprises.data.gouv.fr/entreprise/xtra-pc-432196095']),
'wobz ex dalvin':fix('Industrie / Manufacture',['https://www.wobz.com/','https://www.wobz.com/fr/nous-connaitre']),
'panel du centre communal d action sociale ccas':fix('Administration / Collectivité',['https://www.collectivites-locales.gouv.fr/institutions/le-centre-communal-daction-sociale-ccas'],'France','France'),
}

def run(stem):
    jp=OUT/f'{stem}.json';cp=OUT/f'{stem}.csv';data=json.loads(jp.read_text(encoding='utf-8'))
    before=sum(x.get('secteur')=='Inconnu' for x in data['incidents']);resolved=0;corrected=0;applied=[]
    for x in data['incidents']:
        k=norm(x.get('organisation'))
        f=FIX.get(k)
        if not f:continue
        oldsec=x.get('secteur');changed=False
        for field in ('secteur','territoire','localisation'):
            if field in f and x.get(field)!=f[field]:x[field]=f[field];changed=True
        old=list(x.get('sources') or []);new=list(dict.fromkeys(old+f.get('sources',[])))
        if new!=old:x['sources']=new;changed=True
        if changed:
            applied.append(x.get('organisation'))
            if oldsec=='Inconnu' and x.get('secteur')!='Inconnu':resolved+=1
            else:corrected+=1
            if x.get('evolution')!='nouveau':x['evolution']='enrichi'
    after=sum(x.get('secteur')=='Inconnu' for x in data['incidents'])
    data['metadata']['company_research_v8']={'before_sector_unknown':before,'resolved_sector_unknown':resolved,'remaining_sector_unknown':after,'other_data_corrections':corrected,'applied_to':applied,'method':'high-confidence residual mapping from official company/service sites, official registries, source-native sector metadata only when corroborated by actual victim activity, plus apostrophe-safe identity matching','evidence_policy':'no source-native label is accepted when it conflicts with actual victim activity; genuine taxonomy gaps remain Inconnu'}
    jp.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    with cp.open('w',encoding='utf-8',newline='') as fh:
        w=csv.DictWriter(fh,fieldnames=COLS);w.writeheader()
        for x in data['incidents']:
            r={c:x.get(c,'') for c in COLS if c!='source_urls'};r['source_urls']=' | '.join(x.get('sources') or []);w.writerow(r)
    print(stem,'V8 BEFORE',before,'RESOLVED',resolved,'REMAINING',after,'CORRECTED',corrected,'APPLIED',applied,flush=True)

for stem in ('cyberattaque_org_2026','frenchbreaches_2026'):run(stem)
