import json,sys
from pathlib import Path
OUT=Path(__file__).resolve().parent
for run in ['run1','run2']:
 e=json.loads((OUT/(run+'_evidence.json')).read_text())
 for r in e:
  if not any(t.lower() in r['incident']['org'].lower() for t in sys.argv[1:]):continue
  i=r['incident'];print('\n',run,i['org'],i['threat'],i['threat_status'])
  print('ACTORS', {k:v for k,v in r['detail']['fields'].items() if k in ('third_party','threat_actor','initial_access','data_volume')})
  print('DEDUPE',r['dedup_log'])
  for f in r['source_facts']:
   print('FACT', {k:f[k] for k in ['Source_ID','Claim_Status','Summary','Impact','Threat_Actor','Third_Party','Data_Volume_Raw']})
  for c in r['detail']['affected']:print('COUNT',c)
