import json,sys
from pathlib import Path
OUT=Path(__file__).resolve().parent
e=json.loads((OUT/'run2_evidence.json').read_text())
tr=json.loads((OUT/'snapshots/run2/data/source_facts_ai_trace.json').read_text())
mode=sys.argv[1]
if mode=='unknown':
 for r in e:
  i=r['incident']
  if i['sector']!='Inconnu' and i['location']!='Inconnu':continue
  print('\n',i['id'],i['org'],i['sector'],i['location'],i['summary'])
  print('FIELDS',json.dumps(r['detail']['fields'],ensure_ascii=False))
  for f in r['source_facts']:
   print('ACTIVITY',f['Source_ID'],f['Activity_Description'],f['Activity_Sector_Match'],f['Source_Sector_Raw'],json.loads(f['Evidence_JSON'] or '{}').get('Activity_Description'))
  for t in tr:
   if t['item_id'] not in {x['Item_ID'] for x in r['items']}:continue
   resp=t.get('response',{});print('RESPONSE',str(resp)[:1800]);print('REJECT',t['rejections'])
elif mode=='summary':
 for r in e:
  i=r['incident'];print('\n',i['id'],i['org'],'|',i['summary'])
  for k,f in r['detail']['fields'].items():print(k,f['value'],f.get('status'),f.get('evidence'))
elif mode=='contexts':
 for t in tr:
  if not any(x.lower() in t['organisation'].lower() for x in sys.argv[2:]):continue
  print('\n',t['organisation'],t['item_id'],'CONTEXT',t['context'],'RESPONSE',t.get('response'))
