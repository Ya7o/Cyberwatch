import json,urllib.request,concurrent.futures,csv,io
from pathlib import Path
p=Path(__file__).parent
head=json.loads((p/'remote_head.json').read_text());sha=head['sha']
print('HEAD',sha,head['commit']['message'],head['commit']['committer'])
files=['data/snapshot.json','data/items.csv','data/incidents.csv','data/source_facts.csv','data/dedup_ai_daily_usage.csv','data/dedup_ai_daily_cache.csv','data/source_facts_ai_cache.json','data/source_facts_ai_usage.json','data/llm_usage.json','cyberwatch/runner.py','cyberwatch/enrichment.py','cyberwatch/dedup.py','cyberwatch/dedup_ai.py','cyberwatch/duplicate_audit.py','cyberwatch/source_facts.py','cyberwatch/source_facts_ai.py','.github/workflows/collect.yml','cyberwatch/collectors/frenchbreaches.py']
def get(f):
 try:
  with urllib.request.urlopen('https://raw.githubusercontent.com/Ya7o/Cyberwatch/'+sha+'/'+f,timeout=25) as response: b=response.read()
  dest=p/'remote'/f;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(b)
  return f,len(b)
 except Exception as e:return f,str(e)
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:print(list(pool.map(get,files)))
print('REMOTE SNAPSHOT',(p/'remote/data/snapshot.json').read_text())
print('REMOTE DEDUP',(p/'remote/data/dedup_ai_daily_usage.csv').read_text()[-2500:])
served=json.loads((p/'served_incidents.json').read_text())
print('SERVED COUNT',len(served),'UNKNOWN',sum(i.get('sector')=='Inconnu' for i in served),'SAMPLE',list(served[0]))
for row in csv.DictReader((p/'remote/data/incidents.csv').open()):
 if any(t in row.get('Organisation','').lower() for t in ['pass','par','aveyron','curistes','accent','youfid','jouvet']):print('REMOTE_INCIDENT',row)

