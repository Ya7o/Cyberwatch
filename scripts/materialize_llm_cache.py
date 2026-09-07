#!/usr/bin/env python3
"""Réhydrate les réponses LLM acceptées dans ``data/source_facts.csv``.

Le mode par défaut est une simulation. Utiliser ``--write`` après revue du
nombre d'items modifiés. La correspondance est bornée par Item_ID + hash de
contenu ; aucune réponse d'un autre article ne peut être copiée.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import source_facts, store  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="écrit source_facts.csv")
    args = parser.parse_args()

    cache_path = ROOT / "data" / "source_facts_ai_cache.json"
    payload = json.loads(cache_path.read_text(encoding="utf-8"))
    entries = payload.get("entries", {}) if isinstance(payload, dict) else {}
    cache_entries = list(entries.values()) if isinstance(entries, dict) else []
    facts = store.load_source_facts()
    gaps_before = source_facts.semantic_materialization_gaps(facts)
    hydrated, changed = source_facts.materialize_cached_llm_fields(facts, cache_entries)
    gaps_after = source_facts.semantic_materialization_gaps(hydrated)
    print(f"facts={len(facts)} cache_entries={len(cache_entries)} changed={len(changed)}")
    print(f"gaps_before={len(gaps_before)} gaps_after={len(gaps_after)}")
    if changed:
        print("changed_items=" + ",".join(changed))
    if args.write and changed:
        store.save_source_facts(hydrated)
        print(f"wrote={store.SOURCE_FACTS_CSV}")
    elif args.write:
        print("wrote=none")
    return 0 if not gaps_after else 2


if __name__ == "__main__":
    raise SystemExit(main())
