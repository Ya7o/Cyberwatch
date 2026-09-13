#!/usr/bin/env python3
"""Benchmark d'activation du niveau 2 : 20 incidents, hors ligne.

Rejoue le moteur réel — portes, sécurité d'URL, cache, mapper sectoriel — sur
un corpus de cas figés. Le client HTTP, le résolveur DNS et les appels de modèle
sont injectés depuis le fichier de cas : **aucune requête n'est émise**, comme
pour ``validate-business``. Une fixture manquante est un échec bruyant, jamais
un appel réseau silencieux.

Le benchmark s'exécute en mode **actif** : c'est la décision réellement
publiable que l'on mesure. Que le mode shadow ne publie rien est verrouillé par
les tests unitaires, pas ici.

    python scripts/evaluate_external_activity.py \\
        --cases validation/external_activity_20/cases.json \\
        --out validation/external_activity_20/

Sortie : ``report.json`` et ``report.md``. Code de retour 1 si une porte
bloquante échoue — auquel cas le niveau 2 reste en shadow.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import blf_org_enrichment as blf  # noqa: E402
from cyberwatch import config, org_identity, sector_resolution, sector_semantic  # noqa: E402
from cyberwatch import organisation_activity as oa  # noqa: E402
from cyberwatch import organisation_activity_external as engine_module  # noqa: E402
from cyberwatch import organisation_activity_store as evidence_store  # noqa: E402
from cyberwatch import status as status_codes  # noqa: E402
from cyberwatch.http import Budget, FetchResult  # noqa: E402
from cyberwatch.model import Item  # noqa: E402

#: Chaque cas décrit un incident dont le secteur doit être justifié ou refusé.
BENCHMARK_VERSION = "2026-09-13.external-activity.1"


class BenchmarkClient:
    """Client figé : une URL connue rend sa fixture, une inconnue rend 404."""

    def __init__(self, fixtures: dict, base: Path, budget: Budget):
        self.fixtures = fixtures
        self.base = base
        self.run_budget = budget
        self.calls: list[str] = []

    def fetch(self, url, source_budget=None, headers=None, *, url_guard=None,
              allowed_content_types=(), max_content_bytes=0, allow_redirects=True):
        entry = self.fixtures.get(url)
        if entry is None:
            raise AssertionError(f"fixture manquante pour {url}")
        # La garde de cible s'applique avant la requête, exactement comme dans
        # HttpClient : une URL refusée ne consomme aucun budget.
        if url_guard is not None and url_guard(url):
            return FetchResult(False, url, reason_code=status_codes.REASON_URL_REJECTED)
        self.calls.append(url)
        self.run_budget.consume()
        hops = [str(hop) for hop in entry.get("redirect_chain", [])]
        final_url = str(entry.get("final_url") or url)
        if url_guard is not None:
            refused = next((hop for hop in (*hops, final_url) if url_guard(hop)), "")
            if refused:
                return FetchResult(False, url, int(entry.get("status_code", 200)), "",
                                   status_codes.REASON_REDIRECT_REJECTED, 0.0, {}, final_url)
        code = int(entry.get("status_code", 200))
        if code != 200:
            return FetchResult(False, url, code, "", status_codes.REASON_HTTP_ERROR)
        ctype = str(entry.get("content_type", "text/html"))
        if allowed_content_types and ctype.split(";")[0].strip() not in allowed_content_types:
            return FetchResult(False, url, code, "", status_codes.REASON_CONTENT_TYPE)
        body = entry["body"] if "body" in entry else (
            self.base / str(entry["body_file"])).read_text(encoding="utf-8")
        if max_content_bytes and len(body.encode("utf-8")) > max_content_bytes:
            return FetchResult(False, url, code, "", status_codes.REASON_CONTENT_TOO_LARGE)
        return FetchResult(True, url, code, body, status_codes.REASON_OK, 0.0,
                           {"Content-Type": ctype}, final_url)

    def source_budget(self):
        return self.run_budget


def _resolver(dns: dict):
    def resolve(host):
        if host not in dns:
            raise OSError(f"NXDOMAIN {host}")
        return list(dns[host])
    return resolve


def _item(case: dict, item_id: str) -> Item:
    spec = case.get("item", {})
    return Item(
        Item_ID=item_id,
        Source_ID=spec.get("Source_ID", "BONJOURLAFUITE"),
        Organisation_Raw=case["organisation_raw"],
        Organisation_Key=spec.get("Organisation_Key", ""),
        Published_Date=spec.get("Published_Date", "2026-09-12"),
        Sector=config.SECTOR_UNKNOWN,
        Threat=config.THREAT_LEAK,
        Location=spec.get("Location", config.LOC_INCONNU),
        URL=spec.get("URL", "https://bonjourlafuite.eu.org/"),
    )


def _fact(item: Item, website: str, case: dict) -> dict:
    spec = case.get("fact", {})
    return {
        "Item_ID": item.Item_ID, "Source_ID": item.Source_ID,
        "Victim_Website": website,
        "Fine_Location": spec.get("Fine_Location", ""),
        "Source_Sector_Raw": spec.get("Source_Sector_Raw", ""),
        "Activity_Description": "", "Activity_Sector_Match": "",
        "Activity_Sector_Semantic": "", "Evidence_JSON": "{}",
        "Source_Metadata_JSON": "{}",
    }


class _Reference(dict):
    """Référentiel minimal : seule l'URL de validation nous intéresse ici."""


class _Entry:
    def __init__(self, url: str):
        self.sector = ""
        self.location = ""
        self.validation_url = url
        self.reason = ""


def _counting_quote(case: dict, counters: dict):
    answer = case.get("llm")
    if answer is None:
        return None

    def call(_system, _user):
        counters["quote"] += 1
        return dict(answer)
    return call


def _counting_taxonomy(case: dict, counters: dict):
    answer = case.get("taxonomy")

    def call(_system, _user):
        counters["taxonomy"] += 1
        if answer is None:
            return {"sector": config.SECTOR_UNKNOWN, "confidence": 0.0,
                    "reason": "", "evidence": ""}
        return {"confidence": 0.9, "reason": "benchmark", "evidence": "", **answer}
    return call


def _run_pass(case: dict, base: Path, rows: dict, env: dict, counters: dict,
              state: tuple | None = None) -> tuple[dict, dict, dict, tuple]:
    """Une exécution complète, dans l'ordre exact du runner de production.

    ``state`` rejoue sur les mêmes items et faits, ce que fait une collecte
    quotidienne sur un corpus déjà écrit — et ce dont dépend la préservation du
    rapprochement sémantique. Sans lui, on mesurerait l'idempotence d'un corpus
    neuf, qui n'est pas le cas de production.
    """
    urls = list(case.get("owned_urls", []))
    if state is not None:
        items, facts = state
    else:
        items = [_item(case, f"ITM-{case['case_id']}-{index}")
                 for index in range(max(1, len(urls)))]
        facts = [_fact(item, urls[index] if index < len(urls) else "", case)
                 for index, item in enumerate(items)]
    reference = _Reference()
    if case.get("reference_url"):
        from cyberwatch.normalize import organisation_key
        reference[organisation_key(case["organisation_raw"])] = _Entry(case["reference_url"])

    budget = Budget(int(env.get("EXTERNAL_ACTIVITY_MAX_REQUESTS", 12)),
                    float(env.get("EXTERNAL_ACTIVITY_MAX_SECONDS", 60)), "benchmark")
    client = BenchmarkClient(case.get("fixtures", {}), base, budget)
    engine = engine_module.build_engine(
        items, facts, reference, run_id="BENCH", env=env, client=client, rows=rows,
        resolver=_resolver(case.get("dns", {})),
        quote_call=_counting_quote(case, counters),
        now=env.get("BENCH_NOW", "2026-09-13T00:00:00+00:00"))

    blf.enrich(items, facts, provider=engine)
    # Même enchaînement que `runner.execute` : le mapper taxonomique ne voit
    # l'activité découverte que parce qu'il s'exécute après `enrich`.
    sector_semantic.annotate_source_facts(items, facts, reference,
                                          call=_counting_taxonomy(case, counters))
    decision = sector_resolution.resolve_item(items[0], facts[0], reference)
    provenance = blf.metadata(facts[0].get("Source_Metadata_JSON")).get(blf.KEY, {})
    observed = {
        "external_status": provenance.get("external_status", ""),
        "origin": provenance.get("origin", ""),
        "verification_method": provenance.get("verification_method", ""),
        "activity_description": facts[0].get("Activity_Description", ""),
        "evidence_quote": json.loads(facts[0].get("Evidence_JSON") or "{}").get(
            "Activity_Description", ""),
        "evidence_url": provenance.get("evidence_url", ""),
        "sector": decision.sector,
        "sector_status": decision.status,
        "sector_reason": decision.reason,
        "requests": len(client.calls),
        "calls": list(client.calls),
        "deterministic_sector": __import__(
            "cyberwatch.sector", fromlist=["x"]).classify_sector_activity(
                facts[0].get("Activity_Description", "")),
        "identity_verified": bool(provenance.get("organisation_key")),
        "candidate_urls": [c for c in case.get("owned_urls", [])] + (
            [case["reference_url"]] if case.get("reference_url") else []),
    }
    rows_after = evidence_store.load(engine.evidence_rows()) if engine else rows
    return observed, rows_after, dict(facts[0]), (items, facts)


def _base_env(case: dict) -> dict:
    env = {
        "BLF_EXTERNAL_ACTIVITY_ENABLED": "1",
        # Le benchmark mesure la décision réellement publiable.
        "EXTERNAL_ACTIVITY_SHADOW_MODE": "0",
        "EXTERNAL_ACTIVITY_QUOTE_LLM_ENABLED": "1",
    }
    env.update({key: str(value) for key, value in case.get("env", {}).items()})
    return env


def run_case(case: dict, base: Path) -> dict:
    """Exécute un cas, ses passes supplémentaires, et son contrôle d'idempotence."""
    counters = {"quote": 0, "taxonomy": 0}
    started = time.monotonic()
    registry_backup = org_identity.ORGANISATION_IDENTITY_REGISTRY
    org_identity.ORGANISATION_IDENTITY_REGISTRY = dict(case.get("identity_registry", {}))
    try:
        env = _base_env(case)
        rows: dict = {}
        observed, rows, fact, state = _run_pass(case, base, rows, env, counters)
        passes = [observed]
        for extra in case.get("passes", []):
            extra_env = {**env, **{k: str(v) for k, v in extra.get("env", {}).items()}}
            nxt, rows, _fact_next, _ = _run_pass(case, base, rows, extra_env, counters)
            passes.append(nxt)
            if extra.get("expected"):
                nxt["expected"] = extra["expected"]
        # Idempotence : le même corpus rejoué, cache tiède — le cas de production.
        _repeat, _, fact_repeat, _ = _run_pass(case, base, rows, env, dict(counters), state)
        idempotent = fact_repeat == fact
    finally:
        org_identity.ORGANISATION_IDENTITY_REGISTRY = registry_backup

    expected = case.get("expected", {})
    final = passes[-1] if case.get("judge_last_pass") else passes[0]
    diffs = {key: {"attendu": value, "observé": final.get(key)}
             for key, value in expected.items()
             if key in final and final.get(key) != value}
    llm_calls = counters["quote"] + counters["taxonomy"]
    budget_ok = (llm_calls <= int(expected.get("max_llm_calls", 99))
                 and final["requests"] <= int(expected.get("max_requests", 99)))
    return {
        "Case_ID": case["case_id"],
        "Kind": case.get("kind", ""),
        "Tests": case.get("tests", ""),
        "Incident_ID": case.get("incident_id", ""),
        "Item_ID": f"ITM-{case['case_id']}-0",
        "Organisation_Raw": case["organisation_raw"],
        "Organisation_Key": final.get("candidate_urls") and "" or "",
        "Expected_Sector": expected.get("sector", config.SECTOR_UNKNOWN),
        "Candidate_URLs": final["candidate_urls"],
        "Selected_URL": final["evidence_url"],
        "Identity_Verified": final["identity_verified"],
        "Evidence_Quote": final["evidence_quote"][:300],
        "Activity_Description": final["activity_description"],
        "Deterministic_Sector": final["deterministic_sector"],
        "LLM_Called": llm_calls > 0,
        "LLM_Quote_Calls": counters["quote"],
        "LLM_Sector_Calls": counters["taxonomy"],
        "Final_Candidate_Sector": final["sector"],
        "Sector_Status": final["sector_status"],
        "Reason": final["sector_reason"],
        "External_Status": final["external_status"],
        "Origin": final["origin"],
        "Correct": not diffs,
        "Abstained": final["sector"] == config.SECTOR_UNKNOWN,
        "Idempotent": idempotent,
        "HTTP_Requests": final["requests"],
        "Requested_URLs": final["calls"],
        "Budget_Respected": budget_ok,
        "LLM_Calls": llm_calls,
        "Duration": round(time.monotonic() - started, 3),
        "Diff": diffs,
        "Passes": [{k: v for k, v in p.items() if k != "candidate_urls"} for p in passes],
    }


def gates(results: list[dict], expected_count: int = 20) -> list[dict]:
    """Portes bloquantes. Toutes doivent passer pour autoriser l'activation."""
    abstentions_expected = [r for r in results
                            if r["Expected_Sector"] == config.SECTOR_UNKNOWN]
    false_positives = [r["Case_ID"] for r in abstentions_expected
                       if r["Final_Candidate_Sector"] != config.SECTOR_UNKNOWN]
    answerable = [r for r in results if r["Expected_Sector"] != config.SECTOR_UNKNOWN]
    correct_answerable = [r for r in answerable if r["Correct"]]
    identity_errors = [r["Case_ID"] for r in results
                       if r["Final_Candidate_Sector"] != config.SECTOR_UNKNOWN
                       and not r["Identity_Verified"]]
    unjustified = [r["Case_ID"] for r in results
                   if r["Final_Candidate_Sector"] != config.SECTOR_UNKNOWN
                   and not r["Activity_Description"].strip()]
    return [
        {"gate": "cas_executes", "ok": len(results) == expected_count,
         "detail": f"{len(results)}/{expected_count}"},
        {"gate": "zero_faux_positif", "ok": not false_positives, "detail": false_positives},
        {"gate": "zero_erreur_identite", "ok": not identity_errors, "detail": identity_errors},
        {"gate": "zero_secteur_sans_activite_prouvee", "ok": not unjustified,
         "detail": unjustified},
        {"gate": "decisions_correctes",
         "ok": sum(r["Correct"] for r in results) >= expected_count - 2,
         "detail": f"{sum(r['Correct'] for r in results)}/{len(results)}"},
        {"gate": "rappel_sur_cas_repondables",
         "ok": len(answerable) == 0 or len(correct_answerable) / len(answerable) >= 0.85,
         "detail": f"{len(correct_answerable)}/{len(answerable)}"},
        {"gate": "idempotence", "ok": all(r["Idempotent"] for r in results),
         "detail": [r["Case_ID"] for r in results if not r["Idempotent"]]},
        {"gate": "budget_par_cas", "ok": all(r["Budget_Respected"] for r in results),
         "detail": [r["Case_ID"] for r in results if not r["Budget_Respected"]]},
        {"gate": "budget_llm_total", "ok": sum(r["LLM_Calls"] for r in results) <= 8,
         "detail": sum(r["LLM_Calls"] for r in results)},
        {"gate": "budget_reseau_total", "ok": sum(r["HTTP_Requests"] for r in results) <= 30,
         "detail": sum(r["HTTP_Requests"] for r in results)},
    ]


def evaluate(cases_path: Path) -> dict:
    import os
    import tempfile

    payload = json.loads(cases_path.read_text(encoding="utf-8"))
    cases = payload["cases"]
    base = cases_path.parent
    scratch = tempfile.mkdtemp(prefix="cyberwatch-bench-")
    previous = {key: os.environ.get(key) for key in
                ("SECTOR_SEMANTIC_CACHE_PATH", "SECTOR_SEMANTIC_TRACE_PATH",
                 "EXTERNAL_ACTIVITY_TRACE_PATH")}
    os.environ.update({
        "SECTOR_SEMANTIC_CACHE_PATH": str(Path(scratch) / "semantic-cache.json"),
        "SECTOR_SEMANTIC_TRACE_PATH": str(Path(scratch) / "semantic-trace.json"),
        "EXTERNAL_ACTIVITY_TRACE_PATH": str(Path(scratch) / "external-trace.json"),
    })
    try:
        results = [run_case(case, base) for case in cases]
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    verdicts = gates(results, expected_count=len(cases))
    return {
        "version": payload.get("version", BENCHMARK_VERSION),
        "cases": len(results),
        "passed": all(gate["ok"] for gate in verdicts) and len(cases) == 20,
        "gates": verdicts,
        "totals": {
            "correct": sum(r["Correct"] for r in results),
            "abstained": sum(r["Abstained"] for r in results),
            "http_requests": sum(r["HTTP_Requests"] for r in results),
            "llm_calls": sum(r["LLM_Calls"] for r in results),
        },
        "results": results,
    }


def markdown(report: dict) -> str:
    lines = [
        "# Benchmark d'activation — activité externe (niveau 2)",
        "",
        f"Version du corpus : `{report['version']}` — {report['cases']} incidents, "
        "évalués hors ligne.",
        "",
        f"**Verdict : {'PASS' if report['passed'] else 'FAIL'}**",
        "",
        "## Portes bloquantes",
        "",
        "| Porte | Résultat | Détail |",
        "| --- | --- | --- |",
    ]
    for gate in report["gates"]:
        mark = "réussie" if gate["ok"] else "**ÉCHOUÉE**"
        lines.append(f"| `{gate['gate']}` | {mark} | {gate['detail']} |")
    lines += [
        "",
        f"Total : {report['totals']['correct']}/{report['cases']} décisions correctes, "
        f"{report['totals']['abstained']} abstentions, "
        f"{report['totals']['http_requests']} requêtes HTTP, "
        f"{report['totals']['llm_calls']} appels de modèle.",
        "",
        "## Détail par incident",
        "",
        "| Cas | Ce qu'il teste | Attendu | Obtenu | Motif | Req. | LLM | OK |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in report["results"]:
        lines.append(
            f"| `{row['Case_ID']}` | {row['Tests']} | {row['Expected_Sector']} | "
            f"{row['Final_Candidate_Sector']} | `{row['External_Status'] or row['Reason']}` | "
            f"{row['HTTP_Requests']} | {row['LLM_Calls']} | "
            f"{'oui' if row['Correct'] else '**non**'} |")
    failures = [row for row in report["results"] if not row["Correct"]]
    if failures:
        lines += ["", "## Écarts", ""]
        for row in failures:
            lines.append(f"- `{row['Case_ID']}` : {row['Diff']}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path,
                        default=ROOT / "validation" / "external_activity_20" / "cases.json")
    parser.add_argument("--out", type=Path,
                        default=ROOT / "validation" / "external_activity_20")
    parser.add_argument("--json", action="store_true", help="rapport sur la sortie standard")
    args = parser.parse_args(argv)

    report = evaluate(args.cases)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1, sort_keys=True) + "\n",
        encoding="utf-8")
    (args.out / "report.md").write_text(markdown(report), encoding="utf-8")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        for gate in report["gates"]:
            print(f"  {'ok  ' if gate['ok'] else 'ÉCHEC'} {gate['gate']}: {gate['detail']}")
        print(f"\n{'PASS' if report['passed'] else 'FAIL'} — "
              f"{report['totals']['correct']}/{report['cases']} correctes, "
              f"{report['totals']['http_requests']} requêtes, "
              f"{report['totals']['llm_calls']} appels LLM")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
