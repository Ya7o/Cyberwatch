#!/usr/bin/env python3
import csv, json, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote_plus

import requests
from bs4 import BeautifulSoup

import deep_company_enrichment_v3 as v3

OUT=Path('sources/veillellm')
STEMS=('cyberattaque_org_2026','frenchbreaches_2026')
COLS=v3.COLS
REGISTRY_HOSTS=('annuaire-entreprises.data.gouv.fr','pappers.fr','societe.com','verif.com')
TLD_RX=re.compile(r'(?i)\b(?:https?://)?([a-z0-9][a-z0-9.-]*\.(?:fr|com|net|org|io|app|dev|ai|eu|be|ch|co\.uk))\b')
SIREN_RX=re.compile(r'(?i)(?:SIREN|RCS[^0-9]{0,30})?\b(\d{3})[ .-]?(\d{3})[ .-]?(\d{3})\b')


def relevance(org,text,url=''):
    toks=v3.org_tokens(org)
    hay=v3.fold(text+' '+url)
    if not toks:return 0
    return sum(3 for t in toks if t in hay)+sum(2 for t in toks if t in v3.fold(v3.domain(url)))


def registry_by_siren(siren):
    try:
        r=v3.sess().get('https://recherche-entreprises.api.gouv.fr/search',params={'q':siren,'per_page':5},timeout=10)
        if r.status_code!=200:return None
        for c in r.json().get('results') or []:
            if str(c.get('siren','')).replace(' ','')==siren:
                sec=v3.sector_from_naf(c.get('activite_principale'))
                if sec:return sec,f'https://annuaire-entreprises.data.gouv.fr/entreprise/{siren}',str(c.get('activite_principale') or '')
    except Exception:pass
    return None


def sirens(text):
    out=[]
    for m in SIREN_RX.finditer(text or ''):
        s=''.join(m.groups())
        # French SIREN Luhn validation substantially reduces accidental 9-digit matches.
        if len(s)==9 and s not in out:
            total=0
            for i,ch in enumerate(reversed(s)):
                n=int(ch)
                if i%2==1:
                    n*=2
                    if n>9:n-=9
                total+=n
            if total%10==0:out.append(s)
    return out


def fetch_soup(url):
    r=v3.get(url,timeout=10)
    if not r:return None,None
    try:return BeautifulSoup(r.text,'html.parser'),r.url
    except Exception:return None,r.url


def source_outgoing(row):
    org=row.get('organisation',''); cand=[]
    for src in (row.get('sources') or [])[:2]:
        soup,final=fetch_soup(src)
        if not soup:continue
        srcdom=v3.domain(final or src)
        text=v3.clean(soup.get_text(' ',strip=True))
        # A SIREN explicitly present in the incident source is useful when the article identifies the legal victim.
        if relevance(org,text) >= 3:
            for s in sirens(text):
                x=registry_by_siren(s)
                if x:return ('registry_from_source',x)
        for a in soup.find_all('a',href=True):
            href=requests.compat.urljoin(final or src,a['href'])
            d=v3.domain(href)
            if not href.startswith('http') or d==srcdom or v3.blocked(href):continue
            anchor=v3.clean(a.get_text(' ',strip=True))
            score=relevance(org,anchor,href)
            if score>=3 or any(k in v3.fold(anchor) for k in ('site officiel','site web','website','visiter le site')):
                cand.append((score,href))
    cand.sort(reverse=True)
    return ('links',[u for _,u in cand[:6]])


def explicit_domain_candidates(org,row):
    vals=[]
    for text in (org,row.get('synthese',''),row.get('impact_connu','')):
        for m in TLD_RX.finditer(text or ''):
            host=m.group(1).lower().strip('.')
            if not v3.blocked('https://'+host):vals.append('https://'+host+'/')
    # Common case: organisation itself is a domain-like brand (Productly.app, Kaffir.fr, etc.).
    compact=org.strip().lower().replace(' ','')
    if TLD_RX.search(compact):
        host=TLD_RX.search(compact).group(1)
        if not v3.blocked('https://'+host):vals.insert(0,'https://'+host+'/')
    return list(dict.fromkeys(vals))[:5]


def inspect_company_site(org,url):
    text,links,final=v3.page_text(url)
    if not text:return None
    toks=v3.org_tokens(org); pf=v3.fold(text[:18000]+' '+(final or url))
    if toks and sum(1 for t in toks if t in pf)<max(1,min(2,len(toks))):return None
    pages=[final or url]+links[:4]
    base=(final or url).rstrip('/')
    pages += [base+'/mentions-legales',base+'/mentions-legales/',base+'/legal-mentions',base+'/a-propos',base+'/about',base+'/qui-sommes-nous']
    combined=text
    used=final or url
    for p in list(dict.fromkeys(pages))[1:7]:
        t,_,f=v3.page_text(p)
        if t:combined+=' '+t
    for s in sirens(combined):
        x=registry_by_siren(s)
        if x:return ('registry_from_legal_notice',x[0],x[1],x[2])
    sec=v3.classify_text(combined,'official')
    if sec:return ('official_site',sec,used,'')
    return None


def search_siren(org):
    queries=[f'"{org}" SIREN',f'"{org}" "activité" entreprise']
    toks=v3.org_tokens(org)
    for q in queries:
        for title,snip,u in v3.parse_ddg(q):
            d=v3.domain(u); hay=title+' '+snip
            if not any(d==h or d.endswith('.'+h) for h in REGISTRY_HOSTS):continue
            if relevance(org,hay,u)<3:continue
            for s in sirens(hay+' '+u):
                x=registry_by_siren(s)
                if x:return ('registry_from_search',x[0],x[1],x[2])
    return None


def search_official(org):
    queries=[f'"{org}" "site officiel"',f'"{org}" "mentions légales"']
    seen=set(); cand=[]
    for q in queries:
        for title,snip,u in v3.parse_ddg(q):
            if not u or v3.blocked(u):continue
            if u in seen:continue
            seen.add(u)
            sc=relevance(org,title+' '+snip,u)
            if sc>=5:cand.append((sc,u))
    cand.sort(reverse=True)
    for _,u in cand[:5]:
        x=inspect_company_site(org,u)
        if x:return x
    return None


def linkedin_fallback(org):
    # Secondary fallback only: require a LinkedIn company result matching the organisation and an explicit industry phrase.
    mapping=[
      ('Numérique / Technologie',('développement de logiciels','software development','technologie, information et internet','it services and it consulting','services et conseil informatiques','telecommunications')),
      ('Services aux entreprises',('business consulting and services','services et conseil aux entreprises','facilities services','environmental services','services de conseil en environnement','staffing and recruiting','advertising services','legal services','accounting')),
      ('Industrie / Manufacture',('manufacturing','industrial machinery manufacturing','fabrication de machines','motor vehicle manufacturing')),
      ('Commerce / Distribution',('retail','commerce de détail','wholesale','commerce de gros')),
      ('Finance / Assurance',('financial services','insurance','banking')),
      ('Santé',('hospitals and health care','pharmaceutical manufacturing','medical practices')),
      ('Éducation / Formation',('higher education','education administration programs','professional training and coaching')),
      ('Transport / Logistique',('transportation, logistics, supply chain and storage','airlines and aviation','truck transportation')),
      ('Construction / BTP',('construction','real estate')),
      ('Énergie / Utilities',('utilities','oil and gas','renewable energy')),
      ('Sport',('spectator sports','sports teams and clubs')),
    ]
    for title,snip,u in v3.parse_ddg(f'site:linkedin.com/company "{org}"'):
        if 'linkedin.com' not in v3.domain(u) or relevance(org,title+' '+snip,u)<3:continue
        low=v3.fold(title+' '+snip)
        for sec,phrases in mapping:
            if any(v3.fold(p) in low for p in phrases):return ('linkedin_secondary',sec,u,'')
    return None


def enrich(row):
    if row.get('secteur')!='Inconnu':return row,None
    org=v3.clean(row.get('organisation',''))
    if not org:return row,None

    so=source_outgoing(row)
    if so and so[0]=='registry_from_source':
        sec,ev,code=so[1]; row['secteur']=sec; row['sources']=list(dict.fromkeys(row.get('sources',[])+[ev])); return row,('registry_from_source',sec)
    links=so[1] if so and so[0]=='links' else []
    for u in explicit_domain_candidates(org,row)+links:
        x=inspect_company_site(org,u)
        if x:
            method,sec,ev,code=x; row['secteur']=sec; row['sources']=list(dict.fromkeys(row.get('sources',[])+[ev])); return row,(method,sec)
    x=search_siren(org)
    if x:
        method,sec,ev,code=x; row['secteur']=sec; row['sources']=list(dict.fromkeys(row.get('sources',[])+[ev])); return row,(method,sec)
    x=search_official(org)
    if x:
        method,sec,ev,code=x; row['secteur']=sec; row['sources']=list(dict.fromkeys(row.get('sources',[])+[ev])); return row,(method,sec)
    x=linkedin_fallback(org)
    if x:
        method,sec,ev,code=x; row['secteur']=sec; row['sources']=list(dict.fromkeys(row.get('sources',[])+[ev])); return row,(method,sec)
    return row,None


def run(stem):
    jp=OUT/f'{stem}.json';cp=OUT/f'{stem}.csv';data=json.loads(jp.read_text(encoding='utf-8'));inc=data['incidents']
    before=sum(x.get('secteur')=='Inconnu' for x in inc); stats={}
    targets=[(i,dict(x)) for i,x in enumerate(inc) if x.get('secteur')=='Inconnu']
    with ThreadPoolExecutor(max_workers=10) as ex:
        fut={ex.submit(enrich,x):i for i,x in targets}
        for f in as_completed(fut):
            i=fut[f]
            try:r,res=f.result()
            except Exception as e:
                print('ERR',stem,i,type(e).__name__,str(e)[:100],flush=True);continue
            inc[i]=r
            if res:stats[res[0]]=stats.get(res[0],0)+1
    after=sum(x.get('secteur')=='Inconnu' for x in inc)
    data['incidents']=inc
    data['metadata']['company_research_v4']={
      'before_sector_unknown':before,'resolved':before-after,'remaining_sector_unknown':after,'resolved_by':stats,
      'method':'incident-source outgoing links/domain -> official site/legal notice -> SIREN/APE public registry -> exact SIREN search -> official-site search -> exact LinkedIn industry fallback',
      'evidence_policy':'no forced taxonomy mapping; SIREN/APE validated against French public registry; official/secondary evidence URL retained'
    }
    jp.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    with cp.open('w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=COLS);w.writeheader()
        for x in inc:
            r={k:x.get(k,'') for k in COLS if k!='source_urls'};r['source_urls']=' | '.join(x.get('sources',[]));w.writerow(r)
    print(stem,'V4 BEFORE',before,'RESOLVED',before-after,'REMAINING',after,'BY',stats,flush=True)

if __name__=='__main__':
    for s in STEMS:run(s)
