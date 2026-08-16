#!/usr/bin/env python3
import csv,json,re,difflib,unicodedata
from concurrent.futures import ThreadPoolExecutor,as_completed
from pathlib import Path
import requests
from bs4 import BeautifulSoup

import deep_company_enrichment_v3 as v3

OUT=Path('sources/veillellm'); STEMS=('cyberattaque_org_2026','frenchbreaches_2026'); COLS=v3.COLS

MANUAL={
 'groupe t2mc':('Services aux entreprises','https://www.groupet2mc.fr/','',None),
 'erdil':('Numérique / Technologie','https://www.erdil.fr/','Besançon, Bourgogne-Franche-Comté',None),
 'detenteurs d armes a nouveau dans le viseur':('Commerce / Distribution','https://www.armurerie-lavaux.com/informations-legales.html','Neufchâteau, Grand Est','Armurerie Lavaux'),
}

NAME_SECTOR=[
 ('Commerce / Distribution',r'\b(armurerie|supermarch[ée]|hypermarch[ée]|magasin|boutique|commerce|distributeur|grossiste|concessionnaire)\b'),
 ('Santé',r'\b(h[oô]pital|clinique|pharmacie|laboratoire m[ée]dical|ehpad|centre hospitalier|cabinet dentaire)\b'),
 ('Éducation / Formation',r'\b(universit[ée]|lyc[ée]e|coll[eè]ge|[ée]cole|centre de formation|acad[ée]mie)\b'),
 ('Finance / Assurance',r'\b(banque|assurance|mutuelle|cr[ée]dit)\b'),
 ('Transport / Logistique',r'\b(a[ée]roport|compagnie a[ée]rienne|transport|logistique|fret)\b'),
 ('Numérique / Technologie',r'\b(t[ée]l[ée]com|cloud|logiciel|software|informatique|cyber|datacenter|data center|esn\b)\b'),
 ('Énergie / Utilities',r'\b([ée]nergie|[ée]lectricit[ée]|service des eaux|eau potable|gaz)\b'),
 ('Construction / BTP',r'\b(construction|btp|immobilier|travaux publics)\b'),
 ('Services aux entreprises',r'\b(cabinet de conseil|avocats?|expertise comptable|recrutement|nettoyage industriel|s[ée]curit[ée] priv[ée]e|bureau d.[ée]tudes)\b'),
]

SOURCE_SECTOR=[
 ('Commerce / Distribution',r'\b(commerce de d[ée]tail|commerce de gros|armurerie|vente en ligne|e-commerce|distributeur de|grossiste en|concession automobile|magasin sp[ée]cialis[ée])\b'),
 ('Santé',r'\b([ée]tablissement de sant[ée]|centre hospitalier|h[oô]pital|clinique|pharmacie|laboratoire de biologie|ehpad|cabinet m[ée]dical|cabinet dentaire)\b'),
 ('Éducation / Formation',r'\b([ée]tablissement scolaire|centre de formation|organisme de formation|universit[ée]|lyc[ée]e|coll[eè]ge|[ée]cole sup[ée]rieure|enseignement sup[ée]rieur)\b'),
 ('Finance / Assurance',r'\b([ée]tablissement bancaire|compagnie d.assurance|soci[ée]t[ée] d.assurance|banque|mutuelle|services financiers|courtier en assurance)\b'),
 ('Transport / Logistique',r'\b(compagnie a[ée]rienne|entreprise de transport|transporteur|prestataire logistique|logistique et transport|a[ée]roport|fret)\b'),
 ('Sport',r'\b(f[ée]d[ée]ration sportive|club sportif|club de football|club de rugby|association sportive|ligue de football)\b'),
 ('Numérique / Technologie',r'\b([ée]diteur de logiciels|d[ée]veloppement de logiciels|services informatiques|entreprise informatique|entreprise technologique|op[ée]rateur t[ée]l[ée]com|h[ée]bergeur|cloud provider|cybers[ée]curit[ée]|data center|datacenter)\b'),
 ('Énergie / Utilities',r'\b(fournisseur d.[ée]nergie|producteur d.[ée]lectricit[ée]|distribution d.[ée]lectricit[ée]|service des eaux|gestion de l.eau|assainissement|gestion des d[ée]chets)\b'),
 ('Industrie / Manufacture',r'\b(fabricant de|fabrication de|entreprise industrielle|site industriel|usine de|m[ée]canique de pr[ée]cision|industrie manufacturi[eè]re)\b'),
 ('Construction / BTP',r'\b(entreprise de construction|entreprise du b[âa]timent|travaux publics|promotion immobili[eè]re|promoteur immobilier|agence immobili[eè]re|gestion immobili[eè]re)\b'),
 ('Services aux entreprises',r'\b(cabinet de conseil|cabinet d.avocats?|expertise comptable|cabinet comptable|agence de recrutement|services aux entreprises|nettoyage industriel|nettoyage professionnel|prestations? d.accueil|s[ée]curit[ée] priv[ée]e|bureau d.[ée]tudes|agence de communication)\b'),
]

def fold(s):return v3.fold(s)

def get_source(row):
    url=(row.get('sources') or [''])[0]
    if not url:return '',url
    r=v3.get(url,timeout=12)
    if not r:return '',url
    soup=BeautifulSoup(r.text,'html.parser')
    for x in soup(['script','style','noscript','svg']):x.decompose()
    parts=[]
    if soup.title:parts.append(soup.title.get_text(' ',strip=True))
    h=soup.find('h1')
    if h:parts.append(h.get_text(' ',strip=True))
    for m in soup.select('meta[name="description"],meta[property="og:description"]'):
        if m.get('content'):parts.append(m['content'])
    parts.append(soup.get_text(' ',strip=True)[:25000])
    return ' '.join(parts),r.url

def explicit_source_sector(org,text):
    ft=fold(text); fo=fold(org); toks=[x for x in fo.split() if len(x)>3]
    # activity phrase must occur in a local context window that also identifies the victim, except where the org name itself contains the activity.
    for sec,pat in NAME_SECTOR:
        if re.search(pat,fo,re.I):return sec
    for sec,pat in SOURCE_SECTOR:
        for m in re.finditer(pat,ft,re.I):
            a=max(0,m.start()-260);b=min(len(ft),m.end()+260);win=ft[a:b]
            if not toks or any(t in win for t in toks[:4]):return sec
    return None

def names(c):return v3.candidate_names(c)

def sim(a,b):return difflib.SequenceMatcher(None,fold(a),fold(b)).ratio()

def fuzzy_registry(org,source_text):
    if len(fold(org))<4:return None
    try:
        r=v3.sess().get('https://recherche-entreprises.api.gouv.fr/search',params={'q':org,'per_page':25},timeout=12)
        if r.status_code!=200:return None
        res=r.json().get('results') or []
    except Exception:return None
    src=fold(source_text); scored=[]
    for c in res:
        ns=names(c); best=max([sim(org,n) for n in ns] or [0])
        sec=v3.sector_from_naf(c.get('activite_principale'))
        if not sec:continue
        legal=max(ns,key=lambda n:sim(org,n)) if ns else ''
        source_match=len(fold(legal))>=5 and fold(legal) in src
        siege=c.get('siege') if isinstance(c.get('siege'),dict) else {}
        active=(siege.get('etat_administratif') in (None,'A'))
        scored.append((best,source_match,active,c,sec,legal))
    if not scored:return None
    scored.sort(key=lambda x:(x[1],x[0],x[2]),reverse=True)
    best=scored[0]; second=scored[1][0] if len(scored)>1 else 0
    # Conservative acceptance only: explicit legal-name evidence in source, or almost-exact unique textual match.
    accept = best[1] and best[0]>=0.65
    if best[0]>=0.94 and best[0]-second>=0.07 and best[2]:accept=True
    if not accept:return None
    c=best[3];siren=str(c.get('siren') or '')
    if not siren:return None
    return best[4],f'https://annuaire-entreprises.data.gouv.fr/entreprise/{siren}',best[5],str(c.get('activite_principale') or '')

def clean_noisy_org(row,text):
    org=row.get('organisation','');fo=fold(org)
    # Generic title used instead of victim: Armurerie Lavaux is explicitly named in source/title.
    if 'detenteurs d armes' in fo and 'armurerie lavaux' in fold(text):return 'Armurerie Lavaux'
    patterns=[
      r'^(.*?)\s+(?:frapp[ée]e?|touch[ée]e?|vis[ée]e?|menac[ée]e?|pirat[ée]e?)\s+par\b',
      r'^(.*?)\s+(?:victime)\s+d',
    ]
    for p in patterns:
        m=re.match(p,org,re.I)
        if m and len(m.group(1).strip())>=3:return m.group(1).strip()
    return org

def enrich(row):
    if row.get('secteur')!='Inconnu':return row,None
    org=row.get('organisation',''); key=fold(org)
    if key in MANUAL:
        sec,ev,loc,neworg=MANUAL[key];row['secteur']=sec
        if loc:row['localisation']=loc
        if neworg:row['organisation']=neworg
        row['sources']=list(dict.fromkeys(row.get('sources',[])+[ev]));return row,('manual_official',sec)
    text,_=get_source(row)
    cleanorg=clean_noisy_org(row,text)
    if cleanorg!=org:
        row['organisation']=cleanorg;org=cleanorg
    sec=explicit_source_sector(org,text)
    if sec:
        row['secteur']=sec;return row,('source_explicit_activity',sec)
    if row.get('territoire') in ('France','La Réunion','Mayotte','Inconnu'):
        x=fuzzy_registry(org,text)
        if x:
            sec,ev,legal,ape=x;row['secteur']=sec;row['sources']=list(dict.fromkeys(row.get('sources',[])+[ev]));return row,('fuzzy_registry_with_evidence',sec)
    return row,None

def run(stem):
    jp=OUT/f'{stem}.json';cp=OUT/f'{stem}.csv';data=json.loads(jp.read_text(encoding='utf-8'));inc=data['incidents']
    before=sum(x.get('secteur')=='Inconnu' for x in inc);stats={}
    targets=[(i,dict(x)) for i,x in enumerate(inc) if x.get('secteur')=='Inconnu']
    with ThreadPoolExecutor(max_workers=10) as ex:
        fut={ex.submit(enrich,x):i for i,x in targets}
        for f in as_completed(fut):
            i=fut[f]
            try:r,res=f.result()
            except Exception as e:print('ERR',stem,i,type(e).__name__,str(e)[:100],flush=True);continue
            inc[i]=r
            if res:stats[res[0]]=stats.get(res[0],0)+1
    after=sum(x.get('secteur')=='Inconnu' for x in inc)
    data['incidents']=inc;data['metadata']['company_research_v5']={'before_sector_unknown':before,'resolved':before-after,'remaining_sector_unknown':after,'resolved_by':stats,'method':'manual official evidence for known misses + explicit victim activity in incident source + conservative fuzzy French public-registry match requiring source/legal-name evidence or near-exact unique match','evidence_policy':'no forced mapping; unresolved taxonomy gaps remain Inconnu'}
    jp.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    with cp.open('w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=COLS);w.writeheader()
        for x in inc:
            r={k:x.get(k,'') for k in COLS if k!='source_urls'};r['source_urls']=' | '.join(x.get('sources',[]));w.writerow(r)
    print(stem,'V5 BEFORE',before,'RESOLVED',before-after,'REMAINING',after,'BY',stats,flush=True)

if __name__=='__main__':
    for s in STEMS:run(s)
