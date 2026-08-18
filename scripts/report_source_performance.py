#!/usr/bin/env python3
"""Affiche la ventilation de performance du dernier run instrumenté."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import store

FIELDS = (
    "Collect_Duration_s", "Processing_Duration_s",
    "Org_Registry_Duration_s", "Org_Official_Site_Duration_s",
    "Qualification_LLM_Duration_s", "SourceFacts_LLM_Duration_s",
    "Other_Processing_Duration_s",
)


def _num(row: dict, key: str) -> float:
    try:
        return float(row.get(key) or 0)
    except (TypeError, ValueError):
        return 0.0


def main() -> int:
    rows = store.load_run_sources()
    if not rows:
        print("SOURCE_PERF no_runs=1")
        return 0
    run_id = next((row.get("Run_ID", "") for row in reversed(rows) if row.get("Run_ID")), "")
    selected = [row for row in rows if row.get("Run_ID") == run_id]
    if not any(any(row.get(field) for field in FIELDS) for row in selected):
        print(f"SOURCE_PERF run={run_id} instrumented=0")
        return 0
    print(f"SOURCE_PERF run={run_id} sources={len(selected)}")
    for row in selected:
        q_cost = _num(row, "Qualification_LLM_Cost_USD")
        sf_cost = _num(row, "SourceFacts_LLM_Cost_USD")
        print(
            f"{row.get('Source_ID','')}: total={_num(row,'Duration_s'):.1f}s "
            f"collect={_num(row,'Collect_Duration_s'):.1f}s "
            f"process={_num(row,'Processing_Duration_s'):.1f}s "
            f"registry={_num(row,'Org_Registry_Duration_s'):.1f}s/{row.get('Org_Registry_Calls') or 0} "
            f"official={_num(row,'Org_Official_Site_Duration_s'):.1f}s/{row.get('Org_Official_Site_Calls') or 0} "
            f"q_llm={_num(row,'Qualification_LLM_Duration_s'):.1f}s/{row.get('Qualification_LLM_Calls') or 0} "
            f"sf_llm={_num(row,'SourceFacts_LLM_Duration_s'):.1f}s/{row.get('SourceFacts_LLM_Calls') or 0} "
            f"sf_cache=accepted:{row.get('SourceFacts_Accepted_Cache_Hits') or 0}/"
            f"abstained:{row.get('SourceFacts_Abstained_Cache_Hits') or 0} "
            f"sf_migrate_null={row.get('SourceFacts_Legacy_Null_Migrations') or 0} "
            f"sf_skip_legacy_null={row.get('SourceFacts_Legacy_Null_Skips') or 0} "
            f"sf_miss={row.get('SourceFacts_Semantic_First_Misses') or 0} "
            f"sf_retry={row.get('SourceFacts_Semantic_Retries') or 0}/"
            f"recovered:{row.get('SourceFacts_Recovered_On_Retry') or 0}/"
            f"new_abstain:{row.get('SourceFacts_New_Abstentions') or 0} "
            f"other={_num(row,'Other_Processing_Duration_s'):.1f}s "
            f"llm_cost=${q_cost + sf_cost:.6f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
