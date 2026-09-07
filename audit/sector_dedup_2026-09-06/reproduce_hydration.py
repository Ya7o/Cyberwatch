import sys,json,urllib.request,concurrent.futures,hashlib,datetime
from pathlib import Path
p=Path(__file__).parent;root=p.parents[1];sys.path.insert(0,str(root))
from cyberwatch.collectors.feed import stable_frenchbreaches_detail_text
from cyberwatch.sector_activity import activity_from_text
r=json.loads((p/'local_evidence.json').read_text())
targets=[t for t in r['targets'] if t['item']['Source_ID']=='FRENCHBREACHES']
def get(t):
 i=t['item'];u=i['URL']
 try:
  req=urllib.request.Request(u,headers={'User-Agent':'Cyberwatch-read-only-audit'})
  with urllib.request.urlopen(req,timeout=20) as response:b=response.read()
  out=p/'sources';out.mkdir(exist_ok=True);(out/(i['Item_ID']+'.html')).write_bytes(b)
  parsed=stable_frenchbreaches_detail_text(b.decode());(out/(i['Item_ID']+'.txt')).write_text(parsed)
  result={'item_id':i['Item_ID'],'url':u,'fetched_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'html_bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'parsed_chars':len(parsed),'parsed_start':parsed[:850],'activity':activity_from_text(i['Organisation_Raw'],parsed)}
  print(json.dumps(result,ensure_ascii=False));return result
 except Exception as e:return {'url':u,'error':str(e)}
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:res=list(pool.map(get,targets))
(p/'source_manifest.json').write_text(json.dumps(res,ensure_ascii=False,indent=2))
