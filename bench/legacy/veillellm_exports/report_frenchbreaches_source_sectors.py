#!/usr/bin/env python3
import json,re
from pathlib import Path
import requests
from bs4 import BeautifulSoup
p=Path('sources/veillellm/frenchbreaches_2026.json')
d=json.loads(p.read_text(encoding='utf-8'))
s=requests.Session();s.headers['User-Agent']='Mozilla/5.0 Cyberwatch source-sector audit'
rows=[x for x in d['incidents'] if x.get('secteur')=='Inconnu']
print('UNKNOWN',len(rows))
for x in rows:
    u=(x.get('sources') or [''])[0]
    label=''; about=''
    try:
        r=s.get(u,timeout=12)
        soup=BeautifulSoup(r.text,'html.parser')
        text=' '.join(soup.stripped_strings)
        m=re.search(r'Secteur\s+([^|#]{2,80}?)(?=\s+(?:Fuite|Cyber|Données|À propos|##|Ce que|$))',text,re.I)
        # Prefer links whose visible text starts with Secteur.
        for a in soup.find_all('a'):
            t=' '.join(a.stripped_strings)
            if t.lower().startswith('secteur '):
                label=t[8:].strip();break
        if not label and m: label=m.group(1).strip()
        h2s=soup.find_all(['h2','h3'])
        for h in h2s:
            if 'propos' in h.get_text(' ',strip=True).lower():
                nxt=h.find_next(['p','div'])
                if nxt: about=nxt.get_text(' ',strip=True)[:240]
                break
    except Exception as e: label='ERR:'+type(e).__name__
    print('\t'.join([x.get('organisation',''),label,about,u]))
