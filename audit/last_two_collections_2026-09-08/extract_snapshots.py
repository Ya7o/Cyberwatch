"""Read immutable Git snapshots; write audit evidence only, without network or LLM."""
import csv, io, json, subprocess, sys
from pathlib import Path
from collections import Counter
ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
REFS = {'before':'d1ae0d4', 'run1':'f402377', 'run2':'1fcfd09'}
def git(*args):
    return subprocess.check_output(['git',*args],cwd=ROOT)
def read(ref, path):
    raw=git('show',f'{ref}:{path}').decode('utf-8-sig')
    return list(csv.DictReader(io.StringIO(raw))) if path.endswith('.csv') else json.loads(raw)
def dump(path,obj):
    path.write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n')
def main():
    snapshots={}
    for name,ref in REFS.items():
        folder=OUT/'snapshots'/name
        folder.mkdir(parents=True,exist_ok=True)
        paths=git('ls-tree','-r','--name-only',ref,'data','assets/data').decode().splitlines()
        for path in paths:
            dest=folder/path
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes(git('show',f'{ref}:{path}'))
        s={p:read(ref,p) for p in ['data/items.csv','data/incidents.csv','assets/data/incidents.json','assets/data/facts.json','data/source_facts.csv','data/source_facts_ai_trace.json','data/sector_resolution.csv','data/source_facts_retry_queue.json']}
        snapshots[name]=s
        print(name,ref)
        for p,data in s.items():
            print(p,len(data),list(data[0] if isinstance(data,list) and data else data)[:60])
    dump(OUT/'snapshot_refs.json',{k:git('rev-parse',v).decode().strip() for k,v in REFS.items()})
    for prev,name in [('before','run1'),('run1','run2')]:
        print('\nDELTA',name)
        for path,key in [('data/items.csv','Item_ID'),('data/incidents.csv','Incident_ID'),('assets/data/incidents.json','id')]:
            old={i[key]:i for i in snapshots[prev][path]}; new={i[key]:i for i in snapshots[name][path]}
            delta={'added':[v for k,v in new.items() if k not in old], 'removed':[v for k,v in old.items() if k not in new], 'changed':[{'id':k,'diff':{f:[old[k].get(f),v.get(f)] for f in v if old[k].get(f)!=v.get(f)}} for k,v in new.items() if k in old and old[k]!=v]}
            dump(OUT/(name+'_'+Path(path).stem+('_site' if path.startswith('assets') else '')+'_delta.json'),delta)
            print(path,json.dumps(delta,ensure_ascii=False))
if __name__=='__main__':main()
