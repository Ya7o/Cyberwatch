"""Benchmark frais de la qualification LLM, sans modifier la base de production.

Le benchmark collecte directement les quatre sources CORE actives hors VEILLE_LLM,
prend les N items normalises les plus recents de chaque source, photographie les
valeurs juste avant ``ai.qualify_item`` (T0), puis applique le LLM sur exactement
le meme echantillon (T1).

Aucun appel a ``ai.finish_run`` et aucune fonction ``store.save_*`` n'est fait :
les CSV de production restent intacts. Le cache LLM est volontairement vide afin
que le benchmark mesure de vrais appels API avec le prompt et le modele courants.
"""

from __future__ import annotations

import argparse
import copy
import csv
import datetime as dt
import json
import os
import time
from collections import defaultdict
from pathlib import Path

from cyberwatch import ai, config, enrichment, sources, watchlists
from cyberwatch.collectors import get_collector
from cyberwatch.collectors.base import Window
from cyberwatch.http import Budget, HttpClient
from cyberwatch.runner import entry_to_item

SOURCE_IDS = (
    "FRENCHBREACHES",
    "BONJOURLAFUITE",
    "CYBERATTAQUE_ORG",
    "RANSOMWARE_LIVE",
)

FIELDS = (
    ("Sector", config.SECTOR_UNKNOWN),
    ("Location", config.LOC_INCONNU),
)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _context(entry, max_chars: int = 3000) -> str:
    return " ".join(
        part.strip() for part in (entry.title, entry.summary, entry.content)
        if part and part.strip()
    )[:max_chars]


def _pct(value: int, total: int) -> float:
    return round((100.0 * value / total), 1) if total else 0.0


def _rate(transformed: int, unknown_before: int) -> float:
    return round((100.0 * transformed / unknown_before), 1) if unknown_before else 0.0


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _latest_pairs(result, spec, as_of: str, per_source: int, known_orgs, entity_index, territories, reference):
    by_id = {}
    for entry in result.entries:
        item = entry_to_item(
            entry,
            spec,
            as_of,
            known_orgs,
            entity_index,
            territories,
            reference,
        )
        if item is not None:
            by_id[item.Item_ID] = (item, entry)

    pairs = list(by_id.values())
    pairs.sort(
        key=lambda pair: (
            pair[0].best_date or pair[0].Published_Date,
            pair[0].Published_Date,
            pair[0].Item_ID,
        ),
        reverse=True,
    )
    return pairs[:per_source], len(pairs)


def run(per_source: int, output_dir: Path, start: str | None = None) -> dict:
    api_key = os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY absente : benchmark LLM impossible")

    tz = dt.timezone(dt.timedelta(hours=4))
    now = dt.datetime.now(tz)
    as_of = now.isoformat()
    end = now.date().isoformat()
    start = start or dt.date(now.year, 1, 1).isoformat()
    window = Window(start, end)

    specs_by_id = {spec.source_id: spec for spec in sources.ALL_SOURCES}
    selected_specs = []
    for source_id in SOURCE_IDS:
        spec = specs_by_id.get(source_id)
        if spec is None:
            raise RuntimeError(f"Source absente du referentiel : {source_id}")
        if not spec.active:
            raise RuntimeError(f"Source inactive, benchmark non comparable : {source_id}")
        selected_specs.append(spec)

    known_orgs = watchlists.known_organisations()
    entity_index = watchlists.entity_index()
    territories = watchlists.entity_territories()
    reference = enrichment.load_reference()

    run_budget = Budget(max_requests=1200, max_seconds=1800, label="qualification-bench")
    client = HttpClient(run_budget=run_budget)

    samples: dict[str, list[tuple]] = {}
    collection_meta: dict[str, dict] = {}

    print(f"BENCH_AS_OF={as_of}")
    print(f"BENCH_WINDOW={start}..{end}")
    print(f"BENCH_PER_SOURCE={per_source}")

    for spec in selected_specs:
        started = time.monotonic()
        collector = get_collector(spec.collector)
        result = collector.collect(client, spec, window)
        status_name, coverage = result.resolve()
        pairs, valid_count = _latest_pairs(
            result,
            spec,
            as_of,
            per_source,
            known_orgs,
            entity_index,
            territories,
            reference,
        )
        duration = round(time.monotonic() - started, 1)
        samples[spec.source_id] = pairs
        collection_meta[spec.source_id] = {
            "collector_status": status_name,
            "collector_coverage": coverage,
            "raw_entries": len(result.entries),
            "valid_normalized_items": valid_count,
            "sample_size": len(pairs),
            "calls": result.calls,
            "duration_s": duration,
            "sample_latest": pairs[0][0].best_date if pairs else "",
            "sample_oldest": pairs[-1][0].best_date if pairs else "",
        }
        print(
            "COLLECT "
            f"source={spec.source_id} status={status_name} coverage={coverage} "
            f"raw={len(result.entries)} valid={valid_count} sample={len(pairs)} "
            f"latest={collection_meta[spec.source_id]['sample_latest']} "
            f"oldest={collection_meta[spec.source_id]['sample_oldest']} "
            f"duration_s={duration}"
        )
        if len(pairs) < per_source:
            raise RuntimeError(
                f"Echantillon insuffisant pour {spec.source_id}: {len(pairs)}/{per_source}"
            )

    # Photographie immuable T0 avant tout appel LLM.
    before_by_id = {}
    entry_by_id = {}
    spec_by_id = {}
    ordered_ids = []
    for spec in selected_specs:
        for item, entry in samples[spec.source_id]:
            before_by_id[item.Item_ID] = copy.deepcopy(item)
            entry_by_id[item.Item_ID] = entry
            spec_by_id[item.Item_ID] = spec
            ordered_ids.append(item.Item_ID)

    # Cache volontairement vide : aucune decision historique ne doit masquer un appel.
    state = ai.AiRunState(
        enabled=True,
        api_key=api_key,
        model=os.getenv("OPENAI_MODEL", ai.DEFAULT_MODEL),
        max_calls=_env_int("AI_MAX_CALLS_PER_RUN", 500),
        max_cost=_env_float("AI_MAX_ESTIMATED_COST_USD_PER_RUN", 1.0),
        max_context_chars=_env_int("AI_MAX_CONTEXT_CHARS", 4000),
        max_output_tokens=_env_int("AI_MAX_OUTPUT_TOKENS", 600),
        cache={},
    )

    after_by_id = {}
    llm_started = time.monotonic()
    for spec in selected_specs:
        for item, entry in samples[spec.source_id]:
            ai.qualify_item(item, entry, spec, state)
            after_by_id[item.Item_ID] = copy.deepcopy(item)
    llm_duration = round(time.monotonic() - llm_started, 1)

    decisions_by_item = {}
    for row in state.cache.values():
        decisions_by_item[row.get("Item_ID", "")] = row

    detail_rows = []
    t0_rows = []
    t1_rows = []
    changed_rows = []

    for item_id in ordered_ids:
        before = before_by_id[item_id]
        after = after_by_id[item_id]
        entry = entry_by_id[item_id]
        decision = decisions_by_item.get(item_id, {})
        base = {
            "Source_ID": before.Source_ID,
            "Item_ID": item_id,
            "Date": before.best_date,
            "Organisation": before.Organisation_Raw,
            "Title": before.Title,
            "URL": before.URL,
        }
        t0_rows.append({
            **base,
            "Threat": before.Threat,
            "Sector": before.Sector,
            "Location": before.Location,
        })
        t1_rows.append({
            **base,
            "Threat": after.Threat,
            "Sector": after.Sector,
            "Location": after.Location,
        })
        detail = {
            **base,
            "Sector_T0": before.Sector,
            "Sector_T1": after.Sector,
            "Location_T0": before.Location,
            "Location_T1": after.Location,
            "Sector_LLM": decision.get("Sector", ""),
            "Sector_Confidence": decision.get("Sector_Confidence", ""),
            "Sector_Evidence": decision.get("Sector_Evidence", ""),
            "Location_LLM": decision.get("Location", ""),
            "Location_Confidence": decision.get("Location_Confidence", ""),
            "Location_Evidence": decision.get("Location_Evidence", ""),
            "Context": _context(entry),
        }
        detail_rows.append(detail)
        if before.Sector != after.Sector or before.Location != after.Location:
            changed_rows.append(detail)

    summary_rows = []
    for source_id in (*SOURCE_IDS, "TOTAL"):
        ids = [
            item_id for item_id in ordered_ids
            if source_id == "TOTAL" or before_by_id[item_id].Source_ID == source_id
        ]
        n = len(ids)
        for field_name, unknown in FIELDS:
            u0 = sum(getattr(before_by_id[item_id], field_name) == unknown for item_id in ids)
            u1 = sum(getattr(after_by_id[item_id], field_name) == unknown for item_id in ids)
            transformed = u0 - u1
            summary_rows.append({
                "Source": source_id,
                "Field": field_name,
                "N": n,
                "Unknown_T0": u0,
                "Unknown_T0_pct": _pct(u0, n),
                "Qualified_by_LLM": transformed,
                "Unknown_T1": u1,
                "Unknown_T1_pct": _pct(u1, n),
                "Transformation_pct": _rate(transformed, u0),
            })

    output_dir.mkdir(parents=True, exist_ok=True)
    _write_csv(output_dir / "bench_t0.csv", t0_rows)
    _write_csv(output_dir / "bench_t1.csv", t1_rows)
    _write_csv(output_dir / "bench_detail.csv", detail_rows)
    _write_csv(output_dir / "bench_changed.csv", changed_rows)
    _write_csv(output_dir / "bench_summary.csv", summary_rows)

    payload = {
        "as_of": as_of,
        "window": {"start": start, "end": end},
        "per_source": per_source,
        "sources": list(SOURCE_IDS),
        "collection": collection_meta,
        "ai": {
            "model": state.model,
            "prompt_version": ai.PROMPT_VERSION,
            "calls_attempted": state.calls_attempted,
            "calls_succeeded": state.calls_succeeded,
            "calls_failed": state.calls_failed,
            "calls_budget_blocked": state.calls_budget_blocked,
            "candidates": state.candidates,
            "input_tokens": state.input_tokens,
            "output_tokens": state.output_tokens,
            "reasoning_tokens": state.reasoning_tokens,
            "total_tokens": state.total_tokens,
            "estimated_cost_usd": round(state.estimated_cost_usd, 6),
            "duration_s": llm_duration,
        },
        "summary": summary_rows,
        "changed_count": len(changed_rows),
    }
    (output_dir / "summary.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    md = []
    md.append("# Benchmark qualification LLM")
    md.append("")
    md.append(f"- As of: `{as_of}`")
    md.append(f"- Fenetre de collecte: `{start}` -> `{end}`")
    md.append(f"- Echantillon: **{per_source} items x {len(SOURCE_IDS)} sources = {per_source * len(SOURCE_IDS)} items**")
    md.append(f"- Modele: `{state.model}` ; prompt: `{ai.PROMPT_VERSION}`")
    md.append("")
    md.append("| Source | Champ | N | Inconnu T0 | % T0 | Qualifies LLM | Inconnu T1 | % T1 | Transformation |")
    md.append("|---|---|---:|---:|---:|---:|---:|---:|---:|")
    for row in summary_rows:
        md.append(
            f"| {row['Source']} | {row['Field']} | {row['N']} | "
            f"{row['Unknown_T0']} | {row['Unknown_T0_pct']:.1f}% | "
            f"{row['Qualified_by_LLM']} | {row['Unknown_T1']} | "
            f"{row['Unknown_T1_pct']:.1f}% | {row['Transformation_pct']:.1f}% |"
        )
    md.append("")
    md.append("## Usage LLM")
    md.append("")
    md.append(f"- Candidats: {state.candidates}")
    md.append(f"- Appels: {state.calls_attempted} ; succes: {state.calls_succeeded} ; echecs: {state.calls_failed}")
    md.append(f"- Tokens: {state.total_tokens} ; cout estime: ${state.estimated_cost_usd:.6f}")
    md.append(f"- Duree LLM: {llm_duration:.1f}s")
    md.append(f"- Valeurs effectivement changees: {len(changed_rows)} items")
    md.append("")
    md.append("## Collecte")
    md.append("")
    for source_id in SOURCE_IDS:
        meta = collection_meta[source_id]
        md.append(
            f"- {source_id}: sample={meta['sample_size']}, "
            f"dates={meta['sample_oldest']}..{meta['sample_latest']}, "
            f"status={meta['collector_status']}, coverage={meta['collector_coverage']}%, "
            f"valid={meta['valid_normalized_items']}"
        )

    summary_md = "\n".join(md) + "\n"
    (output_dir / "summary.md").write_text(summary_md, encoding="utf-8")

    print("\n=== BENCH SUMMARY ===")
    print(summary_md)
    print("=== CHANGED QUALIFICATIONS ===")
    if not changed_rows:
        print("NONE")
    for row in changed_rows:
        print(json.dumps(row, ensure_ascii=False))

    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--per-source", type=int, default=30)
    parser.add_argument("--output", default="bench_output")
    parser.add_argument("--start", default="")
    args = parser.parse_args()
    if args.per_source <= 0:
        parser.error("--per-source doit etre > 0")
    run(args.per_source, Path(args.output), args.start or None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
