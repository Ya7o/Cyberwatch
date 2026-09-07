from pathlib import Path
import json
import sys

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from cyberwatch.collectors.feed import stable_frenchbreaches_detail_text
from cyberwatch.sector_activity import activity_from_text
from cyberwatch.sector import classify_sector_activity

audit = root / 'audit/sector_dedup_2026-09-06'
for row in json.loads((audit / 'local_evidence.json').read_text())['targets']:
    item = row['item']
    path = audit / 'sources' / (item['Item_ID'] + '.html')
    if not path.exists():
        continue
    text = stable_frenchbreaches_detail_text(path.read_text())
    activity, proof = activity_from_text(item['Organisation_Raw'], text)
    print(item['Organisation_Raw'], len(text), classify_sector_activity(activity), activity)
    if not activity or classify_sector_activity(activity) == 'Inconnu':
        print('\n'.join(line for line in text.splitlines() if any(w in line for w in ('Les Curistes', 'Aveyron', 'plateforme')))[0:2400])
