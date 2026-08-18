#!/usr/bin/env python3
"""Réapplique le cache LLM compatible après CREATE, sans appel réseau."""

from __future__ import annotations

import json

from cyberwatch import store
from cyberwatch.rebuild_cache import reapply_cached_qualifications


def main() -> int:
    items = store.load_items()
    rows = store.load_ai_qualifications()
    stats = reapply_cached_qualifications(items, rows)
    store.save_items(items)
    print(json.dumps(stats, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
