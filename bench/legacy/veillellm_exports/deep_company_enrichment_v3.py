#!/usr/bin/env python3
import csv, html, json, re, threading, time, unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote_plus, urlparse, parse_qs, unquote

import requests
from bs4 import BeautifulSoup

OUT = Path('sources/veillellm')
STEMS = ('cyberattaque_org_2026', 'frenchbreaches_2026')
COLS = ['date','organisation','territoire','localisation','secteur','type_menace','acteur','statut','score_cyberattaque','impact_connu','source_urls','synthese','evolution']
SECTORS = {'Administration / Collectivité','Santé','Éducation / Formation','Finance / Assurance','Transport / Logistique','Sport','Commerce / Distribution','Numérique / Technologie','Énergie / Utilities','Industrie / Manufacture','Construction / BTP','Services aux entreprises','Inconnu'}
TL = threading.local()

BLOCKED_DOMAINS = {
    'bing.com','google.com','duckduckgo.com','yahoo.com','facebook.com','instagram.com','x.com','twitter.com','tiktok.com',
    'cyberattaque.org','frenchbreaches.com','pappers.fr','societe.com','verif.com','manageo.fr','kompass.com','wikipedia.org',
    'linkedin.com','crunchbase.com','glassdoor.com','indeed.com'
}
SECONDARY_DOMAINS = {'linkedin.com','pappers.fr','societe.com','annuaire-entreprises.data.gouv.fr'}
STOP_TOKENS = {'groupe','group','sas','sasu','sa','sarl','eurl','ltd','limited','inc','corp','corporation','company','co','france','holding','international','the','les','le','la','de','du','des','and','et'}


def sess():
    if not hasattr(TL, 's'):
        s = requests.Session()
        s.headers.update({'User-Agent':'Mozilla/5.0 (compatible; Cyberwatch/1.0; +https://github.com/Ya7o/Cyberwatch)'})
        TL.s = s
    return TL.s


def fold(s):
    s = unicodedata.normalize('NFKD', str(s or '')).encode('ascii','ignore').decode().lower()
    s = re.sub(r'\b(sas|sasu|sa|sarl|eurl|ltd|limited|inc|corp|corporation|company|co)\b', ' ', s)
    return re.sub(r'[^a-z0-9]+', ' ', s).strip()


def org_tokens(org):
    return [x for x in fold(org).split() if len(x) > 2 and x not in STOP_TOKENS]


def clean(s):
    return re.sub(r'\s+', ' ', html.unescape(str(s or ''))).strip()


def domain(url):
    d = urlparse(url).netloc.lower().split(':')[0]
    return d[4:] if d.startswith('www.') else d


def blocked(url):
    d = domain(url)
    return any(d == x or d.endswith('.' + x) for x in BLOCKED_DOMAINS)


def get(url, timeout=10):
    try:
        r = sess().get(url, timeout=timeout, allow_redirects=True)
        if r.status_code >= 400:
            return None
        return r
    except Exception:
        return None


def page_text(url):
    r = get(url)
    if not r:
        return '', [], ''
    ctype = r.headers.get('content-type','')
    if 'html' not in ctype and '<html' not in r.text[:1000].lower():
        return '', [], r.url
    soup = BeautifulSoup(r.text, 'html.parser')
    for x in soup(['script','style','noscript','svg']):
        x.decompose()
    pieces = []
    title = soup.title.get_text(' ', strip=True) if soup.title else ''
    if title: pieces.append(title)
    for m in soup.select('meta[name="description"],meta[property="og:description"]'):
        if m.get('content'): pieces.append(m['content'])
    for h in soup.select('h1,h2,h3')[:50]:
        pieces.append(h.get_text(' ', strip=True))
    pieces.append(soup.get_text(' ', strip=True)[:45000])
    links = []
    for a in soup.find_all('a', href=True):
        t = fold(a.get_text(' ', strip=True))
        if any(k in t for k in ('a propos','qui sommes nous','notre entreprise','about','company','mentions legales','legal notice','nos metiers','expertises','activites')):
            href = requests.compat.urljoin(r.url, a['href'])
            if domain(href) == domain(r.url): links.append(href)
    return clean(' '.join(pieces)), list(dict.fromkeys(links))[:4], r.url


def parse_ddg(q):
    r = get('https://html.duckduckgo.com/html/?q=' + quote_plus(q), timeout=12)
    if not r: return []
    soup = BeautifulSoup(r.text, 'html.parser')
    out = []
    for res in soup.select('.result')[:8]:
        a = res.select_one('.result__a'); sn = res.select_one('.result__snippet')
        if not a: continue
        href = a.get('href','')
        if 'uddg=' in href:
            try: href = unquote(parse_qs(urlparse(href).query).get('uddg',[''])[0])
            except Exception: pass
        if not href.startswith('http'): continue
        out.append((clean(a.get_text(' ',strip=True)), clean(sn.get_text(' ',strip=True) if sn else ''), href))
    return out


def parse_bing(q):
    r = get('https://www.bing.com/search?q=' + quote_plus(q) + '&count=10', timeout=12)
    if not r: return []
    soup = BeautifulSoup(r.text, 'html.parser')
    out=[]
    for li in soup.select('li.b_algo')[:8]:
        a=li.select_one('h2 a'); p=li.select_one('.b_caption p')
        if not a: continue
        href=a.get('href','')
        # Bing often returns tracking redirects. Keep text for discovery, but never store a Bing redirect as evidence.
        out.append((clean(a.get_text(' ',strip=True)), clean(p.get_text(' ',strip=True) if p else ''), href if href.startswith('http') and 'bing.com/ck/' not in href else ''))
    return out


def search(q):
    rows = parse_ddg(q)
    rows += parse_bing(q)
    ded=[]; seen=set()
    for t,s,u in rows:
        key=(t,s,u)
        if key in seen: continue
        seen.add(key); ded.append((t,s,u))
    return ded


# Exact NAF/APE-to-Cyberwatch mapping. Only ranges with a defensible canonical category are mapped.
def sector_from_naf(code):
    c = re.sub(r'[^0-9A-Z.]','', str(code or '').upper())
    m = re.match(r'^(\d{2})(?:\.(\d{1,2}))?', c)
    if not m: return None
    d = int(m.group(1)); sub = m.group(2) or ''
    if 10 <= d <= 33: return 'Industrie / Manufacture'
    if 35 <= d <= 39: return 'Énergie / Utilities'
    if 41 <= d <= 43: return 'Construction / BTP'
    if 45 <= d <= 47: return 'Commerce / Distribution'
    if 49 <= d <= 53: return 'Transport / Logistique'
    if d == 58 and sub.startswith('2'): return 'Numérique / Technologie'
    if 61 <= d <= 63: return 'Numérique / Technologie'
    if 64 <= d <= 66: return 'Finance / Assurance'
    if d == 68: return 'Construction / BTP'
    if 69 <= d <= 74: return 'Services aux entreprises'
    if d == 75: return 'Santé'
    if d == 78: return 'Services aux entreprises'
    if d == 79: return 'Transport / Logistique'
    if 80 <= d <= 82: return 'Services aux entreprises'
    if d == 84: return 'Administration / Collectivité'
    if d == 85: return 'Éducation / Formation'
    if 86 <= d <= 88: return 'Santé'
    if d == 93 and (sub.startswith('1') or c.startswith('93.1')): return 'Sport'
    if d == 95 and (sub.startswith('1') or c.startswith('95.1')): return 'Numérique / Technologie'
    return None


def candidate_names(c):
    vals=[]
    for k in ('nom_raison_sociale','nom_complet','nom_commercial'):
        v=c.get(k)
        if v: vals.append(str(v))
    for k in ('noms_commerciaux','noms_enseignes'):
        v=c.get(k) or []
        if isinstance(v,list): vals += [str(x) for x in v if x]
    return vals


def registry_lookup(org):
    try:
        r=sess().get('https://recherche-entreprises.api.gouv.fr/search', params={'q':org,'per_page':10}, timeout=12)
        if r.status_code != 200: return None
        data=r.json(); results=data.get('results') or []
    except Exception:
        return None
    target=fold(org)
    exact=[]
    for c in results:
        if any(fold(n) == target for n in candidate_names(c)):
            exact.append(c)
    # Also allow a unique candidate whose normalized legal/commercial name differs only by a leading generic token.
    if not exact:
        toks=set(org_tokens(org))
        close=[]
        for c in results:
            names=candidate_names(c)
            if any(toks and toks <= set(org_tokens(n)) for n in names): close.append(c)
        if len({str(c.get('siren','')) for c in close}) == 1: exact=close
    by_siren={str(c.get('siren','')):c for c in exact if c.get('siren')}
    if len(by_siren) != 1: return None
    c=next(iter(by_siren.values()))
    code=c.get('activite_principale') or ''
    sec=sector_from_naf(code)
    if not sec: return None
    siren=str(c.get('siren'))
    ev=f'https://annuaire-entreprises.data.gouv.fr/entreprise/{siren}'
    return sec, ev, code


PATTERNS = {
'Administration / Collectivité': [(8,r'\b(mairie|municipalit[ée]|commune|préfecture|minist[eè]re|administration publique|collectivit[ée]|chambre de commerce|cci\b|city council|local authority|government agency)\b')],
'Santé': [(8,r'\b(h[oô]pital|hospital|clinique|clinic|pharmaci|laboratoire m[ée]dical|medical laboratory|healthcare|sant[ée] humaine|ehpad|veterinary|v[ée]t[ée]rinaire)\b')],
'Éducation / Formation': [(8,r'\b(universit[ée]|university|school|[ée]cole|coll[eè]ge|lyc[ée]e|enseignement|formation professionnelle|training provider|academy|acad[ée]mie)\b')],
'Finance / Assurance': [(9,r'\b(banque|bank|assurance|insurance|mutuelle|cr[ée]dit|credit union|financial services|fintech|asset management|courtier en assurance)\b')],
'Transport / Logistique': [(8,r'\b(compagnie a[ée]rienne|airline|a[ée]roport|airport|transporteur|transport company|logistique|logistics|freight|fret|shipping|entreposage|travel agency|agence de voyages|tour operator)\b')],
'Sport': [(9,r'\b(f[ée]d[ée]ration sportive|sports? federation|club de (football|rugby|basket|tennis)|football club|rugby club|sports? club|salle de sport|fitness club|activit[ée]s sportives)\b')],
'Commerce / Distribution': [(8,r'\b(commerce de gros|commerce de d[ée]tail|grossiste|wholesaler|retailer|retail chain|magasin|supermarch[ée]|supermarket|e-commerce|boutique en ligne|concessionnaire|dealership|distributeur|distribution de produits|vente de mat[ée]riel)\b')],
'Numérique / Technologie': [(9,r'\b([ée]diteur de logiciels|software (company|publisher|vendor)|saas|cloud provider|h[ée]bergeur|hosting provider|services informatiques|it services|cybers[ée]curit[ée]|cybersecurity|t[ée]l[ée]communications?|telecommunications?|datacenter|data center|d[ée]veloppement logiciel|software development)\b')],
'Énergie / Utilities': [(9,r'\b([ée]nergie|energy company|electric utility|[ée]lectricit[ée]|water utility|service des eaux|gaz|gas utility|oil and gas|assainissement|waste management|gestion des d[ée]chets)\b')],
'Industrie / Manufacture': [(8,r'\b(industriel|industrie manufacturi[eè]re|manufacturer|manufacturing|fabricant|fabrication de|usine|industrial company|production industrielle|sous-traitance industrielle)\b')],
'Construction / BTP': [(8,r'\b(btp\b|construction|travaux publics|g[ée]nie civil|civil engineering|promoteur immobilier|promotion immobili[eè]re|real estate developer|entreprise du b[âa]timent|activit[ée]s immobili[eè]res)\b')],
'Services aux entreprises': [(8,r'\b(cabinet de conseil|consulting firm|consultancy|cabinet d.avocats?|law firm|expertise comptable|accounting firm|recrutement|recruitment|staffing|professional services|services aux entreprises|business services|agence marketing|marketing agency|nettoyage industriel|propret[ée]|facility management|prestations? d.accueil|sécurit[ée] priv[ée]e|private security|bureau d.[ée]tudes|engineering consultancy)\b')]
}


def classify_text(text, source_kind='official'):
    low=fold(text)
    scores=[]
    for sec,pats in PATTERNS.items():
        score=0
        for weight,pat in pats:
            if re.search(pat, low, re.I): score += weight
        if score: scores.append((score,sec))
    scores.sort(reverse=True)
    if not scores: return None
    # One explicit high-confidence activity phrase is sufficient on an official site; secondary snippets require a margin.
    threshold = 8 if source_kind == 'official' else 9
    if scores[0][0] < threshold: return None
    if len(scores)>1 and scores[0][0] <= scores[1][0] + (0 if source_kind=='official' else 2): return None
    return scores[0][1]


def result_relevance(org, title, snippet, url):
    toks=org_tokens(org)
    hay=fold(' '.join((title,snippet,domain(url))))
    if not toks: return 0
    hit=sum(1 for t in toks if t in hay)
    score=hit*3
    d=fold(domain(url))
    score += sum(2 for t in toks if t in d)
    if 'site officiel' in fold(title+' '+snippet) or 'official site' in fold(title+' '+snippet): score += 4
    return score


def discover_official(org):
    queries=[f'"{org}" site officiel', f'"{org}" official website', f'"{org}" entreprise activité', f'"{org}" mentions légales']
    candidates=[]; secondary=[]
    for q in queries:
        for title,snip,u in search(q):
            if not u: continue
            d=domain(u)
            rel=result_relevance(org,title,snip,u)
            if rel < 5: continue
            item=(rel,title,snip,u)
            if any(d==x or d.endswith('.'+x) for x in SECONDARY_DOMAINS): secondary.append(item)
            elif not blocked(u): candidates.append(item)
    candidates.sort(reverse=True, key=lambda x:x[0]); secondary.sort(reverse=True,key=lambda x:x[0])
    return candidates[:5], secondary[:8]


def official_site_classify(org, candidates):
    toks=org_tokens(org)
    for rel,title,snip,u in candidates:
        text, links, final_url = page_text(u)
        if not text: continue
        page_fold=fold(text[:12000])
        if toks and sum(1 for t in toks if t in page_fold) < max(1, min(2,len(toks))):
            continue
        corpus = clean(title+' '+snip+' '+text)
        for link in links[:3]:
            t,_,_ = page_text(link)
            corpus += ' ' + t
        sec=classify_text(corpus, 'official')
        if sec: return sec, final_url or u
    return None


def secondary_classify(org, rows):
    # Require concordant evidence from at least two secondary result snippets, unless one is the French public register.
    evidence=[]
    for rel,title,snip,u in rows:
        sec=classify_text(title+' '+snip, 'secondary')
        if sec: evidence.append((sec,u))
    if not evidence: return None
    for sec,u in evidence:
        if domain(u).endswith('annuaire-entreprises.data.gouv.fr'):
            return sec,u
    counts={}
    for sec,u in evidence: counts[sec]=counts.get(sec,0)+1
    best=max(counts,key=counts.get)
    if counts[best] >= 2:
        u=next(u for sec,u in evidence if sec==best)
        return best,u
    return None


def enrich_one(row):
    if row.get('secteur') != 'Inconnu': return row, None
    org=clean(row.get('organisation'))
    if not org: return row, None

    # 1. French official company register: exact/unique organisation match + APE code.
    reg=registry_lookup(org)
    if reg:
        sec,ev,code=reg
        row['secteur']=sec
        row['sources']=list(dict.fromkeys(row.get('sources',[])+[ev]))
        row['evolution']='enrichi' if row.get('evolution')!='nouveau' else row.get('evolution')
        return row, ('registry', sec, code)

    # 2. Discover and inspect the company's own site, including About / Legal notice / Activities pages.
    official, secondary = discover_official(org)
    x=official_site_classify(org, official)
    if x:
        sec,ev=x
        row['secteur']=sec
        row['sources']=list(dict.fromkeys(row.get('sources',[])+[ev]))
        row['evolution']='enrichi' if row.get('evolution')!='nouveau' else row.get('evolution')
        return row, ('official_site', sec, '')

    # 3. Secondary corroboration: public register / LinkedIn company / Pappers / Societe snippets.
    x=secondary_classify(org, secondary)
    if x:
        sec,ev=x
        row['secteur']=sec
        row['sources']=list(dict.fromkeys(row.get('sources',[])+[ev]))
        row['evolution']='enrichi' if row.get('evolution')!='nouveau' else row.get('evolution')
        return row, ('secondary_corroborated', sec, '')

    return row, None


def run(stem):
    jp=OUT/f'{stem}.json'; cp=OUT/f'{stem}.csv'
    data=json.loads(jp.read_text(encoding='utf-8')); inc=data.get('incidents',[])
    before=sum(x.get('secteur')=='Inconnu' for x in inc)
    stats={'registry':0,'official_site':0,'secondary_corroborated':0}
    targets=[(i,x) for i,x in enumerate(inc) if x.get('secteur')=='Inconnu']
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures={ex.submit(enrich_one, dict(x)):i for i,x in targets}
        for f in as_completed(futures):
            i=futures[f]
            try: row,res=f.result()
            except Exception as e:
                print('ERROR',stem,i,type(e).__name__,str(e)[:120],flush=True); continue
            inc[i]=row
            if res: stats[res[0]] += 1
    after=sum(x.get('secteur')=='Inconnu' for x in inc)
    data['incidents']=inc
    data.setdefault('metadata',{})['company_research_v3']={
        'before_sector_unknown':before,
        'resolved':before-after,
        'remaining_sector_unknown':after,
        'resolved_by':stats,
        'method':'exact French public company registry/APE -> official company website and legal/about/activity pages -> corroborated secondary company sources',
        'evidence_policy':'no forced mapping; search engines are discovery only; evidence URL retained in sources'
    }
    data['metadata']['record_count']=len(inc)
    jp.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    with cp.open('w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=COLS); w.writeheader()
        for x in inc:
            r={k:x.get(k,'') for k in COLS if k!='source_urls'}
            r['source_urls']=' | '.join(x.get('sources',[])); w.writerow(r)
    print(stem, 'BEFORE',before,'RESOLVED',before-after,'REMAINING',after,'BY',stats,flush=True)


if __name__=='__main__':
    for stem in STEMS: run(stem)
