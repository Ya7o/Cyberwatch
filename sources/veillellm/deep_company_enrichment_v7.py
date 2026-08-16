#!/usr/bin/env python3
import csv,json,unicodedata,re
from pathlib import Path
OUT=Path('sources/veillellm')
COLS=['date','organisation','territoire','localisation','secteur','type_menace','acteur','statut','score_cyberattaque','impact_connu','source_urls','synthese','evolution']

def norm(s):
    s=unicodedata.normalize('NFKD',str(s or '')).encode('ascii','ignore').decode().casefold()
    return re.sub(r'[^a-z0-9]+',' ',s).strip()

def f(sector, source, territory=None, location=None):
    d={'secteur':sector,'sources':[source]}
    if territory:d['territoire']=territory
    if location:d['localisation']=location
    return d

# Only mappings supported by primary/official evidence or an explicit legal/public status.
FIX={
# FrenchBreaches + possible overlap
'xplor resamania':f('Numérique / Technologie','https://www.resamania.fr/'),
'etablissement penitentiaire pour mineurs de le pontet':f('Administration / Collectivité','https://www.apij.justice.fr/nos-projets/les-operations-penitentiaires/','France','Le Pontet, Vaucluse'),
'l ordre national des pedicures podologues':f('Santé','https://www.onpp.fr/','France','Paris, Île-de-France'),
'taktikimmo':f('Numérique / Technologie','https://taktikimmo.com/'),
'jeveuxaider gouv fr':f('Administration / Collectivité','https://www.jeveuxaider.gouv.fr/mentions-legales','France','France'),
'smartbox':f('Commerce / Distribution','https://www.smartbox.com/fr/'),
'sapeurs pompiers d indre et loire':f('Administration / Collectivité','https://www.sdis37.fr/','France','Indre-et-Loire'),
'ev lang':f('Éducation / Formation','https://www.france-education-international.fr/test/evlang','France','France'),
'eiffage':f('Construction / BTP','https://www.eiffage.com/'),
'olympique de marseille':f('Sport','https://www.om.fr/fr/mentions-legales','France','Marseille, Provence-Alpes-Côte d’Azur'),
'reglo mobile e leclerc':f('Numérique / Technologie','https://www.reglomobile.fr/'),
'socloz':f('Numérique / Technologie','https://www.socloz.com/'),
'cnrs':f('Administration / Collectivité','https://emploi.cnrs.fr/Pages/Presentation.aspx?lang=FR','France','France'),
'ingenierie systeme inter instituts cnrs':f('Administration / Collectivité','https://emploi.cnrs.fr/Pages/Presentation.aspx?lang=FR','France','France'),
'bibliotheque nationale de france bnf':f('Administration / Collectivité','https://www.bnf.fr/fr/missions-et-organisation-de-la-bnf','France','Paris, Île-de-France'),
'ordoclic':f('Numérique / Technologie','https://www.ordoclic.fr/'),
'dalet':f('Numérique / Technologie','https://www.dalet.com/'),
'trescal':f('Services aux entreprises','https://www.trescal.com/'),
'la centrale de financement':f('Finance / Assurance','https://www.lacentraledefinancement.fr/mentions-legales/','France','Paris, Île-de-France'),
'mon bureau numerique':f('Éducation / Formation','https://tribu.phm.education.gouv.fr/tribu/document/t7Swi3','France','Grand Est'),
'pix orga scolaire':f('Éducation / Formation','https://pix.fr/pix-orga-tos-2025-02-27/','France','France'),
'francecasse fr':f('Commerce / Distribution','https://www.francecasse.fr/','France','France'),
'techni contact':f('Commerce / Distribution','https://www.techni-contact.com/nous.html','France','France'),
'storepascher':f('Commerce / Distribution','https://www.storepascher.com/','France','Pont-à-Marcq, Hauts-de-France'),
'groupe fondasol':f('Services aux entreprises','https://www.groupefondasol.com/fr/','France','Avignon, Provence-Alpes-Côte d’Azur'),
'sos oxygene':f('Santé','https://www.sosoxygene.com/notre-entreprise/','France','Nice, Provence-Alpes-Côte d’Azur'),
'voyages prives':f('Transport / Logistique','https://www.voyage-prive.com/info/InformationsLegales','France','Aix-en-Provence, Provence-Alpes-Côte d’Azur'),
'voyages robin':f('Transport / Logistique','https://www.voyages-robin.com/','France','Issoire, Auvergne-Rhône-Alpes'),
'alumn force':f('Numérique / Technologie','https://www.alumnforce.com/','France','Paris, Île-de-France'),
'resaclick':f('Numérique / Technologie','https://resaclick.net/'),
'unibail westfield':f('Construction / BTP','https://www.urw.com/fr/groupe/qui-nous-sommes'),
'immojeune':f('Numérique / Technologie','https://www.immojeune.com/mentions-legales.html','France','Paris, Île-de-France'),
'multi agences immobilieres francaises 500gb':f('Construction / BTP','https://www.immojeune.com/','France','France'),
'panel du centre communal d action sociale ccas':f('Administration / Collectivité','https://www.service-public.fr/particuliers/vosdroits/F1334','France','France'),
'saint georges le flechard':f('Administration / Collectivité','https://lannuaire.service-public.fr/','France','Saint-Georges-le-Fléchard, Pays de la Loire'),
'alumnforce':f('Numérique / Technologie','https://www.alumnforce.com/','France','Paris, Île-de-France'),
'resaclick':f('Numérique / Technologie','https://resaclick.net/'),
# Cyberattaque.org residuals
'ledger':f('Numérique / Technologie','https://www.ledger.com/fr/the-company','France','France'),
'ledger via prestataire global e':f('Numérique / Technologie','https://www.ledger.com/fr/the-company','France','France'),
'or en cash':f('Commerce / Distribution','https://www.orencash.fr/qui-sommes-nous/','France','France'),
'intoxalock':f('Industrie / Manufacture','https://www.intoxalock.com/about','États-Unis','Des Moines, Iowa'),
'la mie caline biscarrosse':f('Commerce / Distribution','https://www.lamiecaline.com/boutiques/biscarosse/','France','Biscarrosse, Nouvelle-Aquitaine'),
'transitions pro centre val de loire':f('Éducation / Formation','https://www.transitionspro-cvl.fr/nos-dispositifs-et-services/','France','Olivet, Centre-Val de Loire'),
}

def run(stem):
    jp=OUT/f'{stem}.json'; cp=OUT/f'{stem}.csv'; data=json.loads(jp.read_text(encoding='utf-8'))
    before=sum(x.get('secteur')=='Inconnu' for x in data['incidents']); resolved=0; corrected=0; applied=[]
    for x in data['incidents']:
        k=norm(x.get('organisation'))
        fix=FIX.get(k)
        if not fix:continue
        oldsec=x.get('secteur'); changed=False
        for field in ('secteur','territoire','localisation'):
            if field in fix and x.get(field)!=fix[field]:x[field]=fix[field];changed=True
        old=list(x.get('sources') or []); new=list(dict.fromkeys(old+fix.get('sources',[])))
        if new!=old:x['sources']=new;changed=True
        if changed:
            applied.append(x.get('organisation'))
            if oldsec=='Inconnu' and x.get('secteur')!='Inconnu':resolved+=1
            else:corrected+=1
            if x.get('evolution')!='nouveau':x['evolution']='enrichi'
    after=sum(x.get('secteur')=='Inconnu' for x in data['incidents'])
    data['metadata']['company_research_v7']={'before_sector_unknown':before,'resolved_sector_unknown':resolved,'remaining_sector_unknown':after,'other_data_corrections':corrected,'applied_to':applied,'method':'targeted primary-source research of residual public bodies, software/SaaS, finance, sport, health, BTP/engineering, telecom, commerce and transport organisations','evidence_policy':'primary or official evidence only; genuine taxonomy gaps remain Inconnu'}
    jp.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    with cp.open('w',encoding='utf-8',newline='') as fobj:
        w=csv.DictWriter(fobj,fieldnames=COLS);w.writeheader()
        for x in data['incidents']:
            r={c:x.get(c,'') for c in COLS if c!='source_urls'};r['source_urls']=' | '.join(x.get('sources') or []);w.writerow(r)
    print(stem,'V7 BEFORE',before,'RESOLVED',resolved,'REMAINING',after,'CORRECTED',corrected,flush=True)

for stem in ('cyberattaque_org_2026','frenchbreaches_2026'):run(stem)
