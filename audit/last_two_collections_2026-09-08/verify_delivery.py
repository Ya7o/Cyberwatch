import json,re,subprocess,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];OUT=Path(__file__).resolve().parent
read=lambda p:json.loads(p.read_text(encoding='utf-8-sig'))
ledger=read(OUT/'review_ledger.json');metrics=read(OUT/'metrics.json')
assert len(ledger)==73 and len({r['incident_id'] for r in ledger})==73
assert all(metrics['public_matches_run2'].values())
assert read(OUT/'technical_checks.json')['renderer_matches_public']
for name,n in [('run1',68),('run2',73)]:
 evidence=read(OUT/(name+'_evidence.json'));render=read(OUT/(name+'_render.json'))
 assert len(evidence)==n==len(render['rendered'])
 assert {r['incident']['id'] for r in evidence}==set(render['rendered'])
 assert all(r['detail']['version']==3 for r in evidence)
 assert all(r['incident']['items']==len(r['items']) for r in evidence)
for p in [ROOT/'docs/audits/LAST_TWO_COLLECTIONS_2026-09-08.md',OUT/'INCIDENTS.md']:
 content=p.read_text()
 for link in re.findall(r'\]\(([^)]+)\)',content):
  if link.startswith(('http:','https:','#')):continue
  assert (p.parent/link).resolve().exists(),(str(p),link)
assert subprocess.check_output(['git','diff','--name-only'],cwd=ROOT)==b''
assert subprocess.check_output(['git','diff','--cached','--name-only'],cwd=ROOT)==b''
files=[ROOT/'docs/audits/LAST_TWO_COLLECTIONS_2026-09-08.md',OUT/'INCIDENTS.md',OUT/'review_ledger.json',OUT/'metrics.json',OUT/'technical_checks.json',OUT/'snapshot_refs.json',OUT/'run1_evidence.json',OUT/'run2_evidence.json',OUT/'run1_render.json',OUT/'run2_render.json',OUT/'actions_34133415793.log',OUT/'actions_34222636343.log']
result={'result':'PASS','coverage':{'run1':68,'run2':73,'distinct_incidents':73},'tracked_files_unchanged':True,'public_data_and_renderer_match':True,'hashes':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}}
(OUT/'delivery_verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
print('PASS: 141 snapshot fiches, 73 distinct incidents, public JSON and renderer matching, local links valid, tracked files unchanged.')
