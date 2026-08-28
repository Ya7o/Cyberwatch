#!/usr/bin/env python3
import csv
import html
import json
import re
import time
from pathlib import Path
from urllib.parse import quote_plus, urlparse, parse_qs, unquote

import requests
from bs4 import BeautifulSoup

OUT = Path('sources/veillellm')
UA = {'User-Agent':'Mozilla/5.0 (compatible; Cyberwatch/1.0; +https://github.com/Ya7o/Cyberwatch)'}
S = requests.Session(); S.headers.update(UA)

TYPE_VALUES = {'Ransomware','DDoS','Malware','Compromission de compte / messagerie','Intrusion','Fuite de données','Phishing / fraude','Incident tiers','Autre cyber','Inconnu'}
SECTOR_VALUES = {'Administration / Collectivité','Santé','Éducation / Formation','Finance / Assurance','Transport / Logistique','Sport','Commerce / Distribution','Numérique / Technologie','Énergie / Utilities','Industrie / Manufacture','Construction / BTP','Services aux entreprises','Inconnu'}
COLS = ['date','organisation','territoire','localisation','secteur','type_menace','acteur','statut','score_cyberattaque','impact_connu','source_urls','synthese','evolution']
UNKNOWN = {'', 'Inconnu', None}

COUNTRY_PATTERNS = [
 ('La Réunion', r'\b(?:la\s+réunion|réunionnais|réunionnaise|974)\b'),
 ('Mayotte', r'\b(?:mayotte|mahorais|mahoraise|976|mamoudzou)\b'),
 ('France', r'\b(?:france|français|française|paris|lyon|marseille|toulouse|lille|bordeaux|nantes|rennes|strasbourg|montpellier|nice|grenoble|dijon|angers|rouen|reims|metz|nancy|clermont-ferrand)\b'),
 ('Belgique', r'\b(?:belgique|belge|bruxelles|wallonie|flandre)\b'),
 ('Suisse', r'\b(?:suisse|genève|geneve|lausanne|zurich|berne)\b'),
 ('Canada', r'\b(?:canada|canadien|québec|quebec|montréal|montreal|ontario|toronto)\b'),
 ('États-Unis', r'\b(?:états-unis|etats-unis|united states|u\.s\.|usa|american|california|texas|new york|florida)\b'),
 ('Royaume-Uni', r'\b(?:royaume-uni|united kingdom|uk\b|british|london|england|scotland|wales)\b'),
 ('Allemagne', r'\b(?:allemagne|germany|german|berlin|munich|hamburg|frankfurt)\b'),
 ('Espagne', r'\b(?:espagne|spain|spanish|madrid|barcelona|valencia)\b'),
 ('Italie', r'\b(?:italie|italy|italian|rome|milan|turin)\b'),
 ('Pays-Bas', r'\b(?:pays-bas|netherlands|dutch|amsterdam|rotterdam)\b'),
 ('Luxembourg', r'\b(?:luxembourg)\b'),
 ('Australie', r'\b(?:australie|australia|australian|sydney|melbourne)\b'),
 ('Nouvelle-Zélande', r'\b(?:nouvelle-zélande|new zealand|auckland|wellington)\b'),
 ('Inde', r'\b(?:inde|india|indian|mumbai|delhi|bengaluru|bangalore)\b'),
 ('Japon', r'\b(?:japon|japan|japanese|tokyo|osaka)\b'),
 ('Chine', r'\b(?:chine|china|chinese|beijing|shanghai)\b'),
 ('Brésil', r'\b(?:brésil|bresil|brazil|brazilian|são paulo|rio de janeiro)\b'),
]

CITY_RX = re.compile(r'\b(?:à|a|in|based in|situé(?:e)? à|siège(?: social)? (?:à|situé à))\s+([A-ZÀ-ÖØ-Ý][A-Za-zÀ-ÖØ-öø-ÿ\-\'’ ]{2,40})', re.I)

THREAT_RULES = [
 ('Ransomware', [r'\bransomware\b', r'\brançongiciel\b', r'\bchiffre(?:ment|r|és|e)\b', r'\blockbit\b', r'\bqilin\b', r'\bakira\b', r'\bblack basta\b', r'\bdragonforce\b']),
 ('DDoS', [r'\bddos\b', r'déni de service', r'denial of service', r'attaque par saturation']),
 ('Malware', [r'\bmalware\b', r'\bspyware\b', r'\binfostealer\b', r'\btrojan\b', r'cheval de troie', r'\bbotnet\b']),
 ('Compromission de compte / messagerie', [r'compte(?:s)? compromis', r'bo[iî]te(?:s)? mail.*comprom', r'messagerie.*comprom', r'account takeover', r'identifiants? volés?', r'email account compromise']),
 ('Intrusion', [r'\bintrusion\b', r'accès non autorisé', r'acces non autorise', r'système compromis', r'system compromised', r'\bhacking\b', r'\bpiratage\b']),
 ('Fuite de données', [r'fuite de données', r'fuite de donnees', r'\bdata breach\b', r'\bexfiltrat', r'données volées', r'donnees volees', r'données exposées', r'données diffusées', r'leak(?:ed)? data']),
 ('Phishing / fraude', [r'\bphishing\b', r'\bhameçonnage\b', r'\bsmishing\b', r'faux site', r'usurpation d.identité', r'\bfraude\b', r'\barnaque\b']),
]

SECTOR_RULES = [
 ('Administration / Collectivité', [r'\bmairie\b', r'\bcommune\b', r'\bmunicipalit', r'\bville de\b', r'\bpréfecture\b', r'\bministere\b', r'\bministère\b', r'\bdépartement\b', r'\bregion\b', r'\brégion\b', r'\badministration publique\b', r'\bgovernment\b', r'\bcity council\b']),
 ('Santé', [r'\bh[oô]pital\b', r'\bchu\b', r'\bclinique\b', r'\bpharmaci', r'\blaboratoire médical', r'\behpad\b', r'\bhealth(?:care)?\b', r'\bmedical\b']),
 ('Éducation / Formation', [r'\buniversit', r'\blycée\b', r'\blycee\b', r'\bcollège\b', r'\becole\b', r'\bécole\b', r'\bacadémie\b', r'\bschool\b', r'\buniversity\b', r'\bcollege\b']),
 ('Finance / Assurance', [r'\bbanque\b', r'\bbank\b', r'\bassurance\b', r'\binsurance\b', r'\bmutuelle\b', r'\bcredit\b', r'\bcrédit\b', r'\bfinanc']),
 ('Transport / Logistique', [r'compagnie aérienne', r'\bairline\b', r'\baéroport\b', r'\bairport\b', r'\btransport\b', r'\blogistique\b', r'\blogistics\b', r'\bshipping\b', r'\bport\b', r'\bfret\b']),
 ('Sport', [r'\bfédération .*sport', r'\bfederation .*sport', r'\bfootball\b', r'\brugby\b', r'\bbasket', r'\bclub sportif\b', r'\bsports? federation\b', r'\bfédération française de (?:motocyclisme|danse|football|rugby|basket|tennis|judo|cyclisme|natation)\b']),
 ('Commerce / Distribution', [r'\bretail\b', r'\bcommerce\b', r'\bmagasin\b', r'\bsupermarch', r'\bdistribution\b', r'\be-commerce\b', r'\bconcession', r'\bgrossiste\b', r'\bvente de\b']),
 ('Numérique / Technologie', [r'\bsoftware\b', r'\blogiciel\b', r'\bcloud\b', r'\bhébergeur\b', r'\bhebergeur\b', r'\btelecom', r'\btélécom', r'\btechnolog', r'\binformatique\b', r'\bcybersécurité\b', r'\bcybersecurity\b', r'\besn\b', r'\bdatacenter\b']),
 ('Énergie / Utilities', [r'\bénergie\b', r'\benergy\b', r'\bélectricité\b', r'\belectricity\b', r'\bgaz\b', r'\boil\b', r'\bpetrole\b', r'\bpétrole\b', r'\bwater utility\b', r'\butilities\b']),
 ('Industrie / Manufacture', [r'\bindustrie\b', r'\bindustriel', r'\bmanufactur', r'\bfabrication\b', r'\busine\b', r'\bfactory\b']),
 ('Construction / BTP', [r'\bconstruction\b', r'\bbtp\b', r'\bbâtiment\b', r'\bbatiment\b', r'travaux publics', r'\bimmobilier\b', r'\breal estate\b']),
 ('Services aux entreprises', [r'\bconseil\b', r'\bconsulting\b', r'\bavocat\b', r'\blaw firm\b', r'\bcomptab', r'\brecrutement\b', r'\brecruit', r'\bservices professionnels\b', r'\bprofessional services\b']),
]

def clean_text(t):
    return re.sub(r'\s+', ' ', html.unescape(t or '')).strip()

def fetch_text(url, timeout=18):
    try:
        r = S.get(url, timeout=timeout, allow_redirects=True)
        if r.status_code >= 400: return '', r.url
        soup = BeautifulSoup(r.text, 'html.parser')
        for x in soup(['script','style','noscript','svg']): x.decompose()
        return clean_text(soup.get_text(' ', strip=True))[:100000], r.url
    except Exception:
        return '', url

def ddg_search(query, max_results=5):
    url = 'https://html.duckduckgo.com/html/?q=' + quote_plus(query)
    try:
        r = S.get(url, timeout=20)
        if r.status_code >= 400: return []
        soup = BeautifulSoup(r.text, 'html.parser')
        out=[]
        for res in soup.select('.result')[:max_results]:
            a=res.select_one('.result__a'); sn=res.select_one('.result__snippet')
            if not a: continue
            href=a.get('href','')
            if 'uddg=' in href:
                try: href=unquote(parse_qs(urlparse(href).query).get('uddg',[''])[0])
                except Exception: pass
            out.append((clean_text(a.get_text(' ',strip=True)), clean_text(sn.get_text(' ',strip=True) if sn else ''), href))
        return out
    except Exception:
        return []

def infer_threat(text):
    low=text.lower()
    for label, patterns in THREAT_RULES:
        if any(re.search(p, low, re.I) for p in patterns): return label
    if re.search(r'cyberattaque|cyber attack|attaque informatique|security incident|incident de cybersécurité', low, re.I):
        return 'Autre cyber'
    return None

def infer_sector(text):
    low=text.lower()
    scores=[]
    for label, patterns in SECTOR_RULES:
        score=sum(1 for p in patterns if re.search(p, low, re.I))
        if score: scores.append((score,label))
    if not scores: return None
    scores.sort(reverse=True)
    if len(scores)>1 and scores[0][0]==scores[1][0]: return None
    return scores[0][1]

def infer_country(text):
    low=text.lower()
    hits=[]
    for country, pat in COUNTRY_PATTERNS:
        n=len(re.findall(pat, low, re.I))
        if n: hits.append((n,country))
    if not hits: return None
    hits.sort(reverse=True)
    if len(hits)>1 and hits[0][0]==hits[1][0]: return None
    return hits[0][1]

def infer_localisation(text, territory=None):
    # Prefer explicit city/location constructions; reject very long/noisy captures.
    for m in CITY_RX.finditer(text):
        loc=clean_text(m.group(1)).strip(' ,.;:-')
        if 2 < len(loc) <= 45 and not re.search(r'\b(?:une|un|des|le|la|les|son|sa|ses|leur|leurs|plus|suite|partir|travers|cause|propos)\b', loc.lower()):
            return loc
    # If only country is evidenced, that is an honest localisation granularity.
    return territory if territory not in UNKNOWN else None

def article_and_search_context(i):
    contexts=[]; evidence=[]
    for u in i.get('sources',[])[:2]:
        txt, final=fetch_text(u)
        if txt:
            contexts.append(txt); evidence.append(final)
    org=i.get('organisation','').strip()
    # Only search web when something remains unresolved.
    queries=[f'"{org}" entreprise localisation secteur', f'"{org}" company headquarters industry']
    for q in queries:
        results=ddg_search(q, max_results=4)
        for title,snippet,href in results:
            if title or snippet:
                contexts.append(title+' '+snippet)
                if href: evidence.append(href)
        if results: break
        time.sleep(0.4)
    return ' '.join(contexts), list(dict.fromkeys(evidence))

def enrich(i, stats):
    need_sector=i.get('secteur') in UNKNOWN
    need_threat=i.get('type_menace') in UNKNOWN
    need_loc=i.get('localisation') in UNKNOWN
    need_terr=i.get('territoire') in UNKNOWN
    if not (need_sector or need_threat or need_loc or need_terr): return i
    stats['rows_targeted']+=1
    context,evidence=article_and_search_context(i)
    base_context=' '.join([i.get('organisation',''), i.get('impact_connu',''), i.get('synthese',''), context])
    changed=False
    if need_threat:
        v=infer_threat(base_context)
        if v:
            i['type_menace']=v; stats['threat_filled']+=1; changed=True
    if need_sector:
        v=infer_sector(base_context)
        if v:
            i['secteur']=v; stats['sector_filled']+=1; changed=True
    if need_terr:
        v=infer_country(base_context)
        if v:
            i['territoire']=v; stats['territory_filled']+=1; changed=True
    if need_loc:
        v=infer_localisation(base_context, i.get('territoire'))
        if v:
            i['localisation']=v; stats['location_filled']+=1; changed=True
    if evidence:
        i['sources']=list(dict.fromkeys(i.get('sources',[])+evidence[:3]))
    # Never fabricate: if still unresolved after source + web search, use explicit non-documentation marker for location.
    if i.get('localisation') in UNKNOWN:
        i['localisation']='Non documenté publiquement'; stats['location_not_public']+=1; changed=True
    # sector/type retain canonical Inconnu if genuinely unresolved after research, but are non-empty and valid.
    if i.get('secteur') not in SECTOR_VALUES: i['secteur']='Inconnu'
    if i.get('type_menace') not in TYPE_VALUES: i['type_menace']='Inconnu'
    if changed and i.get('evolution')=='inchange': i['evolution']='enrichi'
    return i

def write(stem, data):
    incidents=data.get('incidents',[])
    data.setdefault('metadata',{})['record_count']=len(incidents)
    data['metadata']['field_enrichment']='source_then_web_search_no_guessing_v1'
    data['metadata']['required_nonempty_fields']=['secteur','type_menace','localisation']
    data['metadata']['enrichment_stats']=CURRENT_STATS.copy()
    (OUT/f'{stem}.json').write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    with (OUT/f'{stem}.csv').open('w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=COLS); w.writeheader()
        for i in incidents:
            row={k:i.get(k,'') for k in COLS if k!='source_urls'}
            row['source_urls']=' | '.join(i.get('sources',[])); w.writerow(row)

def run(stem):
    global CURRENT_STATS
    data=json.loads((OUT/f'{stem}.json').read_text(encoding='utf-8'))
    before={
      'sector_unknown':sum(1 for i in data['incidents'] if i.get('secteur') in UNKNOWN),
      'threat_unknown':sum(1 for i in data['incidents'] if i.get('type_menace') in UNKNOWN),
      'location_unknown':sum(1 for i in data['incidents'] if i.get('localisation') in UNKNOWN),
    }
    CURRENT_STATS={'rows_targeted':0,'sector_filled':0,'threat_filled':0,'territory_filled':0,'location_filled':0,'location_not_public':0}
    for idx,i in enumerate(data.get('incidents',[]),1):
        enrich(i,CURRENT_STATS)
        if idx%50==0: print(stem, idx, '/', len(data['incidents']), CURRENT_STATS, flush=True)
        time.sleep(0.05)
    after={
      'sector_unknown':sum(1 for i in data['incidents'] if i.get('secteur') in UNKNOWN),
      'threat_unknown':sum(1 for i in data['incidents'] if i.get('type_menace') in UNKNOWN),
      'location_unknown':sum(1 for i in data['incidents'] if i.get('localisation') in UNKNOWN),
    }
    data['metadata']['enrichment_before']=before; data['metadata']['enrichment_after']=after
    write(stem,data)
    print(stem,'BEFORE',before,'AFTER',after,'STATS',CURRENT_STATS,flush=True)

CURRENT_STATS={}
for STEM in ('cyberattaque_org_2026','frenchbreaches_2026'):
    run(STEM)
