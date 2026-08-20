import csv
from pathlib import Path


def test_print_current_golden_reference_items():
    needles = ('aide à dom 74', 'france titre', 'ants', 'my piscine', 'mypiscine', 'mingat')
    rows = list(csv.DictReader(Path('data/items.csv').open(encoding='utf-8')))
    matches = []
    for row in rows:
        blob = ' '.join(str(row.get(k, '')) for k in ('Organisation_Raw','Organisation_Key','Title')).lower()
        if any(needle in blob for needle in needles):
            matches.append({k: row.get(k, '') for k in (
                'Item_ID','Source_ID','Source_Item_ID','Published_Date','Event_Date',
                'Organisation_Raw','Organisation_Key','Title','URL',
            )})
    assert False, repr(matches)
