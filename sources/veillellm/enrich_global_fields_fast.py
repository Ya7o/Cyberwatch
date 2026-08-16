#!/usr/bin/env python3
"""Evidence-first enrichment, optimized for the 2026 global baselines.
No guessed city: localization uses explicit headquarters/location wording when reliable,
otherwise proven territory, otherwise 'Non documenté publiquement'.
"""
import csv, html, json, re, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote_plus, urlparse, parse_qs, unquote
import requests
from bs4 import BeautifulSoup

OUT=Path('sources/veillellm')
COLS=['date','organisation','territoire','localisation','secteur','type_menace','acteur','statut','score_cyberattaque','impact_connu','source_urls','synthese','evolution']
UNKNOWN={'','Inconnu',None}
TYPE_VALUES={'Ransomware','DDoS','Malware','Compromission de compte / messagerie','Intrusion','Fuite de données','Phishing / fraude','Incident tiers','Autre cyber','Inconnu'}
SECTOR_VALUES={'Administration / Collectivité','Santé','Éducation / Formation','Finance / Assurance','Transport / Logistique','Sport','Commerce / Distribution','Numérique / Technologie','Énergie / Utilities','Industrie / Manufacture','Construction / BTP','Services aux entreprises','Inconnu'}
TL=threading.local()

def session():
    if not hasattr(TL,'s'):
        TL.s=requests.Session(); TL.s.headers.update({'User-Agent':'Mozilla/5.0 (compatible; Cyberwatch/1.0; +https://github.com/Ya7o/Cyberwatch)'})
    return TL.s

def clean(s): return re.sub(r'\s+',' ',html.unescape(s or '')).strip()

def fetch_text(url):
    try:
        r=session().get(url,timeout=8,allow_redirects=True)
        if r.status_code>=400: return '',url
        soup=BeautifulSoup(r.text,'html.parser')
        for x in soup(['script','style','noscript','svg']): x.decompose()
        return clean(soup.get_text(' ',strip=True))[:120000],r.url
    except Exception:return '',url

def search_snippets(org):
    q='"'+org+'" siège activité entreprise OR company headquarters industry'
    try:
        r=session().get('https://html.duckduckgo.com/html/?q='+quote_plus(q),timeout=8)
        if r.status_code>=400:return '',[]
        soup=BeautifulSoup(r.text,'html.parser'); parts=[]; urls=[]
        for res in soup.select('.result')[:5]:
            a=res.select_one('.result__a'); sn=res.select_one('.result__snippet')
            if not a:continue
            href=a.get('href','')
            if 'uddg=' in href:
                try:href=unquote(parse_qs(urlparse(href).query).get('uddg',[''])[0])
                except Exception:pass
            parts.append(clean(a.get_text(' ',strip=True))+' '+clean(sn.get_text(' ',strip=True) if sn else ''))
            if href:urls.append(href)
        return ' '.join(parts),urls
    except Exception:return '',[]

THREATS=[
('Ransomware',[r'\bransomware\b',r'\brançongiciel\b',r'\blockbit\b',r'\bqilin\b',r'\bakira\b',r'\bblack basta\b',r'\bdragonforce\b',r'attaque.*chiffrement']),
('DDoS',[r'\bddos\b',r'déni de service',r'denial of service',r'attaque par saturation']),
('Malware',[r'\bmalware\b',r'\bspyware\b',r'\binfostealer\b',r'\btrojan\b',r'cheval de troie',r'\bbotnet\b']),
('Compromission de compte / messagerie',[r'compte(?:s)? compromis',r'messagerie.*comprom',r'bo[iî]te mail.*comprom',r'account takeover',r'identifiants? volés?']),
('Intrusion',[r'\bintrusion\b',r'accès non autorisé',r'acces non autorise',r'système compromis',r'system compromised',r'\bhacking\b',r'\bpiratage\b']),
('Fuite de données',[r'fuite de données',r'fuite de donnees',r'\bdata breach\b',r'\bexfiltrat',r'données volées',r'donnees volees',r'données exposées',r'données diffusées',r'leak(?:ed)? data']),
('Phishing / fraude',[r'\bphishing\b',r'\bhameçonnage\b',r'\bsmishing\b',r'faux site',r'usurpation d.identité',r'\bfraude\b',r'\barnaque\b'])]
SECTORS=[
('Administration / Collectivité',[r'\bmairie\b',r'\bcommune\b',r'\bmunicipalit',r'\bville de\b',r'\bpréfecture\b',r'\bminist[eè]re\b',r'\bdépartement\b',r'\brégion\b',r'\bgovernment\b',r'\bcity council\b']),
('Santé',[r'\bh[oô]pital\b',r'\bchu\b',r'\bclinique\b',r'\bpharmaci',r'\behpad\b',r'\bhealthcare\b',r'\bmedical center\b']),
('Éducation / Formation',[r'\buniversit',r'\blycée\b',r'\bcollège\b',r'\b[ée]cole\b',r'\bacadémie\b',r'\bschool\b',r'\buniversity\b']),
('Finance / Assurance',[r'\bbanque\b',r'\bbank\b',r'\bassurance\b',r'\binsurance\b',r'\bmutuelle\b',r'\bcrédit\b',r'\bfinancial services\b']),
('Transport / Logistique',[r'compagnie aérienne',r'\bairline\b',r'\baéroport\b',r'\bairport\b',r'\blogistique\b',r'\blogistics\b',r'\bshipping\b',r'\bfret\b',r'\btransporteur\b']),
('Sport',[r'\bfédération française de (?:motocyclisme|danse|football|rugby|basket|tennis|judo|cyclisme|natation)',r'\bfootball club\b',r'\brugby club\b',r'\bsports? federation\b']),
('Commerce / Distribution',[r'\bretailer\b',r'\bretail chain\b',r'\bcommerce\b',r'\bmagasin\b',r'\bsupermarch',r'\bdistributeur\b',r'\be-commerce\b',r'\bconcessionnaire\b',r'\bgrossiste\b']),
('Numérique / Technologie',[r'\bsoftware company\b',r'éditeur de logiciels',r'\bcloud provider\b',r'\bhébergeur\b',r'\btélécom',r'\btelecom',r'\bcybersécurité\b',r'\bcybersecurity company\b',r'\besn\b',r'\bdatacenter\b']),
('Énergie / Utilities',[r'\bénergie\b',r'\benergy company\b',r'\bélectricité\b',r'\belectric utility\b',r'\bgas utility\b',r'\bwater utility\b']),
('Industrie / Manufacture',[r'\bmanufacturer\b',r'\bmanufacturing\b',r'\bindustriel',r'\busine\b',r'\bfabricant\b']),
('Construction / BTP',[r'\bconstruction company\b',r'\bbtp\b',r'travaux publics',r'\bpromoteur immobilier\b',r'\breal estate developer\b']),
('Services aux entreprises',[r'\bconsulting firm\b',r'cabinet de conseil',r'\blaw firm\b',r'cabinet d.avocats?',r'cabinet comptable',r'\brecruitment firm\b',r'\bprofessional services\b'])]
COUNTRIES=[('La Réunion',r'\b(?:la réunion|réunionnais|974)\b'),('Mayotte',r'\b(?:mayotte|mahorais|976|mamoudzou)\b'),('France',r'\b(?:france|français|française)\b'),('Belgique',r'\b(?:belgique|belge)\b'),('Suisse',r'\b(?:suisse|switzerland|swiss)\b'),('Canada',r'\b(?:canada|canadien|canadian|québec|quebec)\b'),('États-Unis',r'\b(?:united states|états-unis|etats-unis|\busa\b|american company)\b'),('Royaume-Uni',r'\b(?:united kingdom|royaume-uni|british|\buk\b)\b'),('Allemagne',r'\b(?:germany|allemagne|german company)\b'),('Espagne',r'\b(?:spain|espagne|spanish company)\b'),('Italie',r'\b(?:italy|italie|italian company)\b'),('Pays-Bas',r'\b(?:netherlands|pays-bas|dutch company)\b'),('Luxembourg',r'\bluxembourg\b'),('Australie',r'\b(?:australia|australie|australian)\b'),('Inde',r'\b(?:india|inde|indian company)\b'),('Japon',r'\b(?:japan|japon|japanese company)\b'),('Brésil',r'\b(?:brazil|brésil|bresil|brazilian)\b')]

HQ_PATTERNS=[
 re.compile(r'(?:siège(?: social)?|basée?|implantée?|située?)\s+(?:est\s+)?(?:à|au|aux|en)\s+([A-ZÀ-ÖØ-Ý][A-Za-zÀ-ÖØ-öø-ÿ\-’\' ]{2,35})(?=[,.;]|\s(?:en|dans|est|et|qui)\b)'),
 re.compile(r'(?:headquartered|based)\s+in\s+([A-Z][A-Za-z .\-]{2,35})(?=[,.;]|\s(?:and|is|which)\b)',re.I)]

def infer_priority(text,rules):
    low=text.lower()
    for label,pats in rules:
        if any(re.search(p,low,re.I) for p in pats):return label
    return None

def infer_sector(text):
    low=text.lower(); scores=[]
    for label,pats in SECTORS:
        score=sum(bool(re.search(p,low,re.I)) for p in pats)
        if score:scores.append((score,label))
    scores.sort(reverse=True)
    if not scores:return None
    if len(scores)>1 and scores[0][0]==scores[1][0]:return None
    return scores[0][1]

def infer_country(text):
    low=text.lower(); hits=[]
    for c,p in COUNTRIES:
        n=len(re.findall(p,low,re.I))
        if n:hits.append((n,c))
    hits.sort(reverse=True)
    if not hits:return None
    if len(hits)>1 and hits[0][0]==hits[1][0]:return None
    return hits[0][1]

def explicit_location(text):
    for rx in HQ_PATTERNS:
        for m in rx.finditer(text):
            loc=clean(m.group(1)).strip(' ,.;:-')
            # reject sentence fragments and generic terms
            if 2<len(loc)<=35 and len(loc.split())<=5 and not re.search(r'\b(?:une|un|des|le|la|les|plus|suite|cause|travers|cadre|secteur|entreprise|société|company)\b',loc.lower()):
                return loc
    return None

def enrich_one(i,source_cache):
    need_s=i.get('secteur') in UNKNOWN; need_t=i.get('type_menace') in UNKNOWN; need_l=i.get('localisation') in UNKNOWN; need_r=i.get('territoire') in UNKNOWN
    if not (need_s or need_t or need_l or need_r):return i,{'target':0}
    sources=i.get('sources',[])[:2]; article=' '.join(source_cache.get(u,('',u))[0] for u in sources)
    existing=' '.join([i.get('organisation',''),i.get('impact_connu',''),i.get('synthese','')])
    base=existing+' '+article
    # First source content; web search only if something remains unresolved.
    if need_t:
        v=infer_priority(base,THREATS)
        if not v and re.search(r'cyberattaque|cyber attack|attaque informatique|incident de cybersécurité',base,re.I):v='Autre cyber'
        if v:i['type_menace']=v
    if need_s:
        v=infer_sector(base)
        if v:i['secteur']=v
    if need_r:
        v=infer_country(base)
        if v:i['territoire']=v
    web=''; extra=[]
    if i.get('secteur') in UNKNOWN or i.get('territoire') in UNKNOWN or i.get('localisation') in UNKNOWN:
        web,extra=search_snippets(i.get('organisation',''))
        ctx=base+' '+web
        if i.get('secteur') in UNKNOWN:
            v=infer_sector(ctx)
            if v:i['secteur']=v
        if i.get('territoire') in UNKNOWN:
            v=infer_country(ctx)
            if v:i['territoire']=v
        if i.get('localisation') in UNKNOWN:
            loc=explicit_location(ctx)
            if loc:i['localisation']=loc
    if i.get('localisation') in UNKNOWN:
        if i.get('territoire') not in UNKNOWN:i['localisation']=i['territoire']
        else:i['localisation']='Non documenté publiquement'
    if extra:i['sources']=list(dict.fromkeys(i.get('sources',[])+extra[:2]))
    if i.get('secteur') not in SECTOR_VALUES:i['secteur']='Inconnu'
    if i.get('type_menace') not in TYPE_VALUES:i['type_menace']='Inconnu'
    return i,{'target':1,'sector_unknown':int(i['secteur']=='Inconnu'),'threat_unknown':int(i['type_menace']=='Inconnu'),'location_bad':int(i['localisation'] in UNKNOWN)}

def run(stem):
    jp=OUT/f'{stem}.json'; cp=OUT/f'{stem}.csv'; data=json.loads(jp.read_text(encoding='utf-8')); inc=data['incidents']
    before={'sector_unknown':sum(x.get('secteur') in UNKNOWN for x in inc),'threat_unknown':sum(x.get('type_menace') in UNKNOWN for x in inc),'location_unknown':sum(x.get('localisation') in UNKNOWN for x in inc)}
    urls=list(dict.fromkeys(u for x in inc if (x.get('secteur') in UNKNOWN or x.get('type_menace') in UNKNOWN or x.get('localisation') in UNKNOWN or x.get('territoire') in UNKNOWN) for u in x.get('sources',[])[:2]))
    cache={}
    with ThreadPoolExecutor(max_workers=18) as ex:
        fut={ex.submit(fetch_text,u):u for u in urls}
        for f in as_completed(fut):cache[fut[f]]=f.result()
    stats={'target':0,'sector_unknown':0,'threat_unknown':0,'location_bad':0}
    # Search requests are also concurrent by incident.
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs={ex.submit(enrich_one,x,cache):idx for idx,x in enumerate(inc)}
        for f in as_completed(futs):
            idx=futs[f]; row,st=f.result(); inc[idx]=row
            for k,v in st.items():stats[k]=stats.get(k,0)+v
    after={'sector_unknown':sum(x.get('secteur') in UNKNOWN for x in inc),'threat_unknown':sum(x.get('type_menace') in UNKNOWN for x in inc),'location_unknown':sum(x.get('localisation') in UNKNOWN for x in inc),'location_non_documented':sum(x.get('localisation')=='Non documenté publiquement' for x in inc)}
    data['metadata']['field_enrichment']='evidence_first_parallel_v2';data['metadata']['enrichment_before']=before;data['metadata']['enrichment_after']=after;data['metadata']['required_nonempty_fields']=['secteur','type_menace','localisation']
    jp.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    with cp.open('w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=COLS);w.writeheader()
        for x in inc:
            row={k:x.get(k,'') for k in COLS if k!='source_urls'};row['source_urls']=' | '.join(x.get('sources',[]));w.writerow(row)
    print(stem,'BEFORE',before,'AFTER',after,'TARGETED',stats['target'],flush=True)

for s in ('cyberattaque_org_2026','frenchbreaches_2026'):run(s)
