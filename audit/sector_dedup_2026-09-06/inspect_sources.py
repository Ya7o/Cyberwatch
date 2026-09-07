import json,sys,urllib.request,hashlib,concurrent.futures
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; out=Path(__file__).parent
r=json.loads((out/'local_evidence.json').read_text())
for t in r['targets']:
 i=t['item']; f=t['facts']; m=json.loads(f.get('Source_Metadata_JSON') or '{}')
 print(i['Item_ID'],i['Organisation_Raw'],i['Source_ID'],i['Sector'],t['resolved_now']['reason'])
 print(' activity=',f.get('Activity_Description'),'match=',f.get('Activity_Sector_Match'))
 print(' url=',i['URL']);print(' summary=',f.get('Summary'))
 print(' metadata=',{k:v for k,v in m.items() if k!='rich_facts'})
 print(' source_context=',[x.get('evidence') for x in m.get('rich_facts',{}).get('timeline',[])])
urls={'remote_head':'https://api.github.com/repos/Ya7o/Cyberwatch/commits/main','served_incidents':'https://ya7o.github.io/Cyberwatch/assets/data/incidents.json','served_status':'https://ya7o.github.io/Cyberwatch/assets/data/status.json'}
def fetch(k,u):
 try:
  req=urllib.request.Request(u,headers={'User-Agent':'Cyberwatch-read-only-audit'})
  with urllib.request.urlopen(req,timeout=25) as res:b=res.read()
  (out/(k+'.json')).write_bytes(b)
  j=json.loads(b)
  print('FETCH',k,len(b),hashlib.sha256(b).hexdigest(),j.get('sha') if isinstance(j,dict) else len(j))
 except Exception as e:print('FETCH_ERROR',k,str(e))
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:list(pool.map(lambda kv:fetch(*kv),urls.items()))
