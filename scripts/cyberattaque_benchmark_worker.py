#!/usr/bin/env python3
"""Exécute un SHA Cyberwatch isolé pour le benchmark offline."""
from __future__ import annotations

import argparse, csv, inspect, json, sys
from pathlib import Path
from types import SimpleNamespace


def main() -> int:
    p = argparse.ArgumentParser(); p.add_argument('--code-root', required=True); p.add_argument('--fixture', required=True); p.add_argument('--items', required=True); p.add_argument('--output', required=True)
    a = p.parse_args(); root = str(Path(a.code_root).resolve()); sys.path.insert(0, root)
    import subprocess
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    from cyberwatch import sources, watchlists
    from cyberwatch.collectors.base import RawEntry
    from cyberwatch.runner import entry_to_item
    try:
        from cyberwatch.runner import _existing_organisations
    except ImportError:
        _existing_organisations = None
    payload = json.loads(Path(a.fixture).read_text(encoding='utf-8'))
    candidates = list(csv.DictReader(Path(a.items).open(encoding='utf-8')))
    known = watchlists.known_organisations(); spec = sources.by_id('CYBERATTAQUE_ORG')
    params = inspect.signature(entry_to_item).parameters
    rows = []
    for raw in payload['articles']:
        entry = RawEntry(**{k:v for k,v in raw.items() if k in inspect.signature(RawEntry).parameters})
        corpus = [SimpleNamespace(**r) for r in candidates if r['Source_ID'] != 'CYBERATTAQUE_ORG' and r['Published_Date'] <= entry.published]
        index = _existing_organisations(corpus) if _existing_organisations else {}
        kwargs = {}
        if 'existing_orgs' in params: kwargs['existing_orgs'] = index
        item = entry_to_item(entry, spec, '2026-08-14T00:00:00+04:00', known, {}, **kwargs)
        rows.append({'Benchmark_Commit': commit, 'Source_Item_ID': entry.source_item_id, 'URL': entry.url, 'Organisation': '' if item is None else item.Organisation_Raw,
                     'Status': 'NO_VICTIM' if item is None else 'SINGLE'})
    Path(a.output).write_text(json.dumps(rows, ensure_ascii=False, sort_keys=True), encoding='utf-8')
    return 0
if __name__ == '__main__': raise SystemExit(main())
