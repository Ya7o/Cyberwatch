#!/usr/bin/env python3
"""Audit live reproductible du resolver Cyberattaque.org, sans écriture DB."""
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import sources, store, watchlists
from cyberwatch.collectors.base import Window
from cyberwatch.collectors.cyberattaque_org import (
    CyberattaqueOrgCollector, is_negated_incident, is_obvious_multi,
    organisation_from_cyberattaque_entry,
)
from cyberwatch.http import Budget, HttpClient
from cyberwatch.normalize import find_known_entity, organisation_key, searchable
from cyberwatch.runner import _existing_organisations

ARTICLE_FIXTURE = ROOT / "tests/fixtures/cyberattaque_org_articles_2026-08-14.json"
COMMITS = {
    "dbd85": "dbd85eaa790f10fa581a1dbbb349cddc0749f305",
    "caa133": "caa133874a00bccf25e07077d7684bb1586c9e11",
    "final": "519d292d7ebc9950f222e557683e8945c6df6d50",
}


def _historical_results() -> dict[str, dict[tuple[str, str], dict]]:
    """Exécute chaque SHA dans son worktree, sans importer son code ici."""
    results = {}
    for label, sha in COMMITS.items():
        with tempfile.TemporaryDirectory(prefix="cw-resolver-") as directory:
            tree = Path(directory) / label
            subprocess.run(["git", "worktree", "add", "--detach", str(tree), sha], cwd=ROOT, check=True, capture_output=True)
            output = Path(directory) / "result.json"
            try:
                subprocess.run([sys.executable, str(ROOT / "scripts/cyberattaque_benchmark_worker.py"), "--code-root", str(tree), "--fixture", str(ARTICLE_FIXTURE), "--items", str(ROOT / "data/items.csv"), "--output", str(output)], cwd=ROOT, check=True, capture_output=True)
            finally:
                subprocess.run(["git", "worktree", "remove", "--force", str(tree)], cwd=ROOT, check=True, capture_output=True)
            rows = json.loads(output.read_text(encoding="utf-8"))
            if len(rows) != 408 or any(row["Benchmark_Commit"] != sha for row in rows):
                raise SystemExit(f"Worker historique invalide : {label}")
            results[label] = {(row["Source_Item_ID"], row["URL"]): row for row in rows}
    return results

def _reference() -> list[dict[str, str]]:
    with tempfile.NamedTemporaryFile(suffix=".csv") as handle:
        subprocess.run(
            [sys.executable, "scripts/materialize_cyberattaque_llm_reference.py", "--output", handle.name],
            cwd=ROOT, check=True, capture_output=True, text=True,
        )
        return list(csv.DictReader(Path(handle.name).open(encoding="utf-8")))


def _candidate_details(entry, index):
    """Même règle que le resolver : exact, unique, et ±14 jours."""
    try:
        published = date.fromisoformat(entry.published[:10])
    except ValueError:
        return [], []
    blob = searchable(" ".join((entry.title, entry.summary, entry.content)))
    close, outside = [], []
    for key, candidate in sorted(index.items()):
        if not re.search(rf"(?<!\w){re.escape(key)}(?!\w)", blob):
            continue
        deltas = [abs((published - date.fromisoformat(value[:10])).days) for value in candidate.dates]
        if min(deltas, default=9999) <= 14:
            close.append((candidate, min(deltas)))
        else:
            outside.append(candidate)
    return close, outside


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, help="CSV détaillé (sinon /tmp).")
    parser.add_argument("--offline", action="store_true", help="Utilise exclusivement la fixture versionnée.")
    parser.add_argument("--capture", action="store_true", help="Capture la fixture WordPress explicitement.")
    parser.add_argument("--check", action="store_true", help="Valide la structure offline et la reproductibilité.")
    args = parser.parse_args()
    reference = _reference()
    if len(reference) != 408:
        raise SystemExit("Golden set invalide : 408 décisions attendues.")
    if args.offline:
        payload = json.loads(ARTICLE_FIXTURE.read_text(encoding="utf-8"))
        if payload.get("article_count") != 408:
            raise SystemExit("Fixture Cyberattaque.org invalide : 408 articles attendus.")
        from cyberwatch.collectors.base import RawEntry
        entries = [RawEntry(**row) for row in payload["articles"]]
    else:
        spec = sources.by_id("CYBERATTAQUE_ORG")
        entries = CyberattaqueOrgCollector().collect(
            HttpClient(Budget(80, 300)), spec, Window("2026-01-01", "2026-08-14")
        ).entries
    if args.capture:
        ARTICLE_FIXTURE.write_text(json.dumps({
            "source": "Cyberattaque.org WordPress API", "captured_at": "2026-08-14",
            "article_count": len(entries), "articles": [entry.__dict__ for entry in entries],
        }, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        print(f"captured={ARTICLE_FIXTURE}; articles={len(entries)}")
    historical = _historical_results()
    print("dbd85_sha=" + COMMITS["dbd85"]); print("caa133_sha=" + COMMITS["caa133"]); print("final_sha=" + COMMITS["final"])
    by_id = {entry.source_item_id: entry for entry in entries}
    by_url = {entry.url: entry for entry in entries}
    # Corpus causal : autres sources exclusivement, à D ou avant. L'article
    # Cyberattaque.org n'est jamais sa propre preuve, ni celle d'un autre.
    all_items = [item for item in store.load_items() if item.Source_ID != "CYBERATTAQUE_ORG"]
    known = watchlists.known_organisations()
    rows = []
    counters = Counter()
    for ref in reference:
        entry = by_id.get(ref["Source_Item_ID"]) or by_url.get(ref["URL"])
        if entry is None:
            rows.append({**ref, "Deterministic_Organisation": "", "Deterministic_Status": "MISSING",
                         "Resolution_Mode": "NO_VICTIM", "Resolver_Candidate": "",
                         "Resolver_Date_Delta": "", "Match": "DIFF"})
            continue
        negated = is_negated_incident(entry.title, entry.summary, entry.content)
        multi = is_obvious_multi(entry.title, entry.summary, entry.content)
        direct = organisation_from_cyberattaque_entry(entry, known, {}) if not (negated or multi) else ""
        candidates = [item for item in all_items if item.Published_Date <= entry.published]
        index = _existing_organisations(candidates)
        close, outside = _candidate_details(entry, index)
        final = historical["final"].get((ref["Source_Item_ID"], ref["URL"]), {}).get("Organisation", "")
        current = historical["caa133"].get((ref["Source_Item_ID"], ref["URL"]), {}).get("Organisation", "")
        dbd = historical["dbd85"].get((ref["Source_Item_ID"], ref["URL"]), {}).get("Organisation", "")
        if negated:
            mode, state = "NEGATED", "NEGATED"
        elif multi:
            mode, state = "MULTI", "MULTI"
        elif direct:
            mode, state = "DIRECT", "SINGLE"
        elif final:
            mode, state = "EXISTING_DB_RESOLVER", "SINGLE"
        else:
            mode, state = "NO_VICTIM", "NO_VICTIM"
        counters[mode] += 1
        attempted = not direct and not negated and not multi
        counters["resolver_attempted"] += int(attempted)
        if attempted:
            counters["resolver_candidates_total"] += len(close) + len(outside)
            counters["resolver_rejected_outside_14_days"] += int(bool(outside) and not close)
            counters["resolver_rejected_multiple_candidates"] += int(len(close) > 1)
            counters["resolver_rejected_no_candidate"] += int(not close)
        counters["resolver_unique_match"] += int(mode == "EXISTING_DB_RESOLVER")
        candidate = close[0][0] if len(close) == 1 else None
        match = organisation_key(final) == organisation_key(ref["LLM_Organisation"])
        classification = (
            "NEGATED_OR_DISPUTED" if mode == "NEGATED" else "MULTI" if mode == "MULTI"
            else "SEMANTIC_DIFFERENCE_ACCEPTED" if not final else "CANONICALISATION"
        )
        rows.append({**ref, "Dbd85_Organisation": dbd, "Dbd85_Status": "SINGLE" if dbd else "NO_VICTIM", "Caa133_Organisation": current, "Caa133_Status": "SINGLE" if current else "NO_VICTIM", "Final_Organisation": final, "Final_Status": state, "Current_Organisation": current, "Deterministic_Organisation": final,
                     "Deterministic_Status": state, "Resolution_Mode": mode,
                     "Resolver_Candidate": "" if not candidate else candidate.organisation,
                     "Resolver_Sources": "" if not candidate else ",".join(candidate.sources),
                     "Resolver_Dates": "" if not candidate else ",".join(candidate.dates),
                     "Resolver_Date_Delta": "" if not candidate else str(close[0][1]),
                     "Diff_Classification": classification,
                     "Match": "MATCH" if match else "DIFF"})
    baseline_match = sum(organisation_key(r["Dbd85_Organisation"]) == organisation_key(r["LLM_Organisation"]) for r in rows)
    current_match = sum(organisation_key(r.get("Current_Organisation", "")) == organisation_key(r["LLM_Organisation"]) for r in rows)
    final_match = sum(r["Match"] == "MATCH" for r in rows)
    print(f"articles_total={len(rows)}")
    print(f"baseline_exact_match={baseline_match}; current_exact_match={current_match}; final_exact_match={final_match}")
    print(f"baseline_diff={len(rows)-baseline_match}; current_diff={len(rows)-current_match}; final_diff={len(rows)-final_match}")
    print(f"delta_current_vs_baseline={current_match-baseline_match}; delta_final_vs_current={final_match-current_match}; delta_final_vs_baseline={final_match-baseline_match}")
    print("high_confidence_diffs=" + str(sum(r["Match"] == "DIFF" and r["LLM_Confidence"] == "HIGH" for r in rows)))
    print("medium_confidence_diffs=" + str(sum(r["Match"] == "DIFF" and r["LLM_Confidence"] == "MEDIUM" for r in rows)))
    for key in ("DIRECT", "EXISTING_DB_RESOLVER", "MULTI", "NEGATED", "NO_VICTIM", "resolver_attempted", "resolver_candidates_total", "resolver_unique_match", "resolver_rejected_no_candidate", "resolver_rejected_multiple_candidates", "resolver_rejected_outside_14_days"):
        print(f"{key.lower()}={counters[key]}")
    output = args.output or Path("/tmp/cyberattaque_resolver_audit.csv")
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)
    print(f"report={output}")
    if args.check:
        # Les entrées causales sont toutes filtrées à D ou avant ; la moindre
        # donnée future serait donc une erreur structurelle du benchmark.
        if any(row.get("Future_Data_Used") == "YES" for row in rows):
            raise SystemExit("Benchmark causal invalide : donnée future détectée.")
        print("check=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
