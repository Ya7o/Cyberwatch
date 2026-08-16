#!/usr/bin/env python3
import csv, html, json, re, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote_plus, urlparse, parse_qs, unquote
import requests
from bs4 import BeautifulSoup

OUT=Path('sources/veillellm')
COLS=['date','organisation','territoire','localisation','secteur','type_menace','acteur','statut','score_cyberattaque','impact_connu','source_urls','synthese','evolution']
UNKNOWN={'','Inconnu',None}
SECTOR_VALUES={'Administration / Collectivité','Santé','Éducation / Formation','Finance / Assurance','Transport / Logistique','Sport','Commerce / Distribution','Numérique / Technologie','Énergie / Utilities','Industrie / Manufacture','Construction / BTP','Services aux entreprises','Inconnu'}
TL=threading.local()

def sess():
    if not hasattr(TL,'s'):
        TL.s=requests.Session(); TL.s.headers.update({'User-Agent':'Mozilla/5.0 (compatible; Cyberwatch/1.0; +https://github.com/Ya7o/Cyberwatch)'})
    return TL.s

def clean(s): return re.sub(r'\s+',' ',html.unescape(s or '')).strip()

def get_text(url):
    try:
        r=sess().get(url,timeout=8,allow_redirects=True)
        if r.status_code>=400:return ''
        soup=BeautifulSoup(r.text,'html.parser')
        for x in soup(['script','style','noscript','svg']):x.decompose()
        return clean(soup.get_text(' ',strip=True))[:100000]
    except Exception:return ''

SECTORS=[
('Administration / Collectivité',[r'\bmairie\b',r'\bmunicipalit',r'\bcommune de\b',r'\bville de\b',r'\bpréfecture\b',r'\bminist[eè]re\b',r'\bgovernment agency\b',r'\bpublic administration\b',r'\bcity council\b',r'\blocal authority\b']),
('Santé',[r'\bh[oô]pital\b',r'\bhospital\b',r'\bclinique\b',r'\bclinic\b',r'\bpharmaci',r'\bpharmaceutical\b',r'\bmedical laboratory\b',r'\bhealthcare provider\b',r'\bhealth system\b',r'\behpad\b']),
('Éducation / Formation',[r'\buniversit',r'\buniversity\b',r'\bcollege\b',r'\blycée\b',r'\bschool\b',r'\b[ée]cole\b',r'\bacadémie\b',r'\btraining provider\b',r'\bcentre de formation\b']),
('Finance / Assurance',[r'\bbank\b',r'\bbanque\b',r'\binsurance\b',r'\bassurance\b',r'\bmutuelle\b',r'\bcredit union\b',r'\bfinancial services\b',r'\bfintech\b',r'\basset management\b']),
('Transport / Logistique',[r'\bairline\b',r'compagnie aérienne',r'\bairport\b',r'\baéroport\b',r'\blogistics\b',r'\blogistique\b',r'\bshipping company\b',r'\bfreight\b',r'\btransport company\b',r'\btransporteur\b',r'\bpostal service\b']),
('Sport',[r'\bsports? federation\b',r'\bfédération .*sport',r'\bfootball club\b',r'\brugby club\b',r'\bbasketball club\b',r'\btennis club\b',r'\bmotorsport federation\b']),
('Commerce / Distribution',[r'\bretail(?:er| chain)?\b',r'\bdistribution company\b',r'\bdistributeur\b',r'\bcommerce de\b',r'\bmagasin\b',r'\bsupermarket\b',r'\bsupermarch',r'\be-commerce\b',r'\bwholesaler\b',r'\bgrossiste\b',r'\bdealership\b',r'\bconcessionnaire\b',r'\bretail company\b']),
('Numérique / Technologie',[r'\bsoftware company\b',r'éditeur de logiciels',r'\bit services\b',r'\binformation technology company\b',r'\btechnology company\b',r'\btech company\b',r'\bcloud provider\b',r'\bhosting provider\b',r'\bhébergeur\b',r'\btelecommunications company\b',r'\btélécommunications\b',r'\bcybersecurity company\b',r'\bdatacenter\b']),
('Énergie / Utilities',[r'\benergy company\b',r'\bénergéticien\b',r'\belectric utility\b',r'\bélectricité\b',r'\bpower company\b',r'\bwater utility\b',r'\bwater company\b',r'\bgas utility\b',r'\boil and gas\b']),
('Industrie / Manufacture',[r'\bmanufacturer\b',r'\bmanufacturing company\b',r'\bindustrial company\b',r'\bindustriel',r'\bfabricant\b',r'\bproduction industrielle\b',r'\bautomotive supplier\b',r'\baerospace manufacturer\b',r'\bchemical manufacturer\b']),
('Construction / BTP',[r'\bconstruction company\b',r'\bconstruction group\b',r'\bcontractor\b',r'\bbtp\b',r'\btravaux publics\b',r'\bcivil engineering\b',r'\breal estate developer\b',r'\bpromoteur immobilier\b']),
('Services aux entreprises',[r'\bconsulting firm\b',r'\bconsultancy\b',r'cabinet de conseil',r'\blaw firm\b',r'cabinet d.avocats?',r'\baccounting firm\b',r'cabinet comptable',r'\brecruitment firm\b',r'\bstaffing company\b',r'\bprofessional services firm\b',r'\bbusiness services\b',r'\bmarketing agency\b',r'\bengineering consultancy\b'])]

def infer(text):
    low=text.lower(); scores=[]
    for label,pats in SECTORS:
        # require at least one strong phrase; count multiple evidence hits
        hits=sum(1 for p in pats if re.search(p,low,re.I))
        if hits:scores.append((hits,label))
    scores.sort(reverse=True)
    if not scores:return None
    if len(scores)>1 and scores[0][0]==scores[1][0]:return None
    return scores[0][1]

def ddg(q):
    try:
        r=sess().get('https://html.duckduckgo.com/html/?q='+quote_plus(q),timeout=8)
        if r.status_code>=400:return '',[]
        soup=BeautifulSoup(r.text,'html.parser');parts=[];urls=[]
        for res in soup.select('.result')[:6]:
            a=res.select_one('.result__a');sn=res.select_one('.result__snippet')
            if not a:continue
            href=a.get('href','')
            if 'uddg=' in href:
                try:href=unquote(parse_qs(urlparse(href).query).get('uddg',[''])[0])
                except Exception:pass
            parts.append(clean(a.get_text(' ',strip=True))+' '+clean(sn.get_text(' ',strip=True) if sn else ''))
            if href:urls.append(href)
        return ' '.join(parts),urls
    except Exception:return '',[]

def bing(q):
    try:
        r=sess().get('https://www.bing.com/search?q='+quote_plus(q)+'&count=8',timeout=8)
        if r.status_code>=400:return '',[]
        soup=BeautifulSoup(r.text,'html.parser');parts=[];urls=[]
        for li in soup.select('li.b_algo')[:6]:
            a=li.select_one('h2 a');p=li.select_one('.b_caption p')
            if not a:continue
            parts.append(clean(a.get_text(' ',strip=True))+' '+clean(p.get_text(' ',strip=True) if p else ''))
            href=a.get('href','');
            if href:urls.append(href)
        return ' '.join(parts),urls
    except Exception:return '',[]

def enrich(row):
    if row.get('secteur')!='Inconnu':return row,False
    org=row.get('organisation','').strip(); base=' '.join([org,row.get('impact_connu',''),row.get('synthese','')])
    for u in row.get('sources',[])[:2]:base+=' '+get_text(u)
    v=infer(base)
    evidence=[]
    if not v:
        queries=[f'"{org}" activité secteur entreprise',f'"{org}" company industry business',f'"{org}" official company about']
        corpus=base
        for q in queries:
            d,du=ddg(q);b,bu=bing(q);corpus+=' '+d+' '+b;evidence+=du[:2]+bu[:2]
            v=infer(corpus)
            if v:break
    if v:
        row['secteur']=v
        if evidence:row['sources']=list(dict.fromkeys(row.get('sources',[])+evidence[:3]))
        if row.get('evolution')=='inchange':row['evolution']='enrichi'
        return row,True
    # Important: do not force a sector when taxonomy has no defensible match.
    return row,False

def run(stem):
    jp=OUT/f'{stem}.json';cp=OUT/f'{stem}.csv';data=json.loads(jp.read_text(encoding='utf-8'));inc=data['incidents']
    before=sum(x.get('secteur')=='Inconnu' for x in inc);changed=0
    targets=[(idx,x) for idx,x in enumerate(inc) if x.get('secteur')=='Inconnu']
    with ThreadPoolExecutor(max_workers=12) as ex:
        fut={ex.submit(enrich,x):idx for idx,x in targets}
        for f in as_completed(fut):
            idx=fut[f];row,ch=f.result();inc[idx]=row;changed+=int(ch)
    after=sum(x.get('secteur')=='Inconnu' for x in inc)
    data['metadata']['deep_sector_research']={'before':before,'resolved':changed,'remaining_canonical_inconnu':after,'method':'source + DuckDuckGo + Bing; no forced mapping when evidence/taxonomy insufficient'}
    jp.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    with cp.open('w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=COLS);w.writeheader()
        for x in inc:
            r={k:x.get(k,'') for k in COLS if k!='source_urls'};r['source_urls']=' | '.join(x.get('sources',[]));w.writerow(r)
    print(stem,'SECTOR BEFORE',before,'RESOLVED',changed,'REMAINING',after,flush=True)

for s in ('cyberattaque_org_2026','frenchbreaches_2026'):run(s)
