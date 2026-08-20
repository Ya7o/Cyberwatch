#!/usr/bin/env python3
"""Certification de clôture du chantier rich facts Cyberattaque.org."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

DEFAULT_GATES = {
    "min_articles": 1,
    "min_rich_coverage": 0.80,
    "min_schema_v2_coverage": 0.75,
    "min_evidence_coverage": 0.98,
    "max_error_rate": 0.02,
    "max_invalid_status": 0,
    "max_confirmed_hypothetical": 0,
}


def certify(audit: dict, gates: dict | None = None) -> dict:
    gates = {**DEFAULT_GATES, **(gates or {})}
    metrics = audit.get("metrics") or {}
    errors = audit.get("quality_errors") or {}
    checks = {
        "articles": int(audit.get("articles") or 0) >= int(gates["min_articles"]),
        "rich_coverage": float(metrics.get("rich_coverage") or 0) >= float(gates["min_rich_coverage"]),
        "schema_v2_coverage": float(metrics.get("schema_v2_coverage") or 0) >= float(gates["min_schema_v2_coverage"]),
        "evidence_coverage": float(metrics.get("evidence_coverage") or 0) >= float(gates["min_evidence_coverage"]),
        "error_rate": float(metrics.get("error_rate") or 0) <= float(gates["max_error_rate"]),
        "invalid_status": int(errors.get("invalid_status") or 0) <= int(gates["max_invalid_status"]),
        "confirmed_hypothetical": int(errors.get("confirmed_with_hypothetical_evidence") or 0) <= int(gates["max_confirmed_hypothetical"]),
    }
    return {"certified": all(checks.values()), "checks": checks, "gates": gates, "metrics": metrics, "quality_errors": errors}


def markdown(result: dict, audit: dict) -> str:
    status = "CERTIFIÉ" if result["certified"] else "NON CERTIFIÉ"
    lines = [f"# Cyberattaque.org rich facts — {status}", "", f"Articles audités : **{audit.get('articles', 0)}**", "", "## Gates"]
    for key, passed in result["checks"].items():
        lines.append(f"- {'PASS' if passed else 'FAIL'} — `{key}`")
    lines += ["", "## Métriques", "```json", json.dumps(result.get("metrics") or {}, ensure_ascii=False, indent=2, sort_keys=True), "```", "", "## Erreurs qualité", "```json", json.dumps(result.get("quality_errors") or {}, ensure_ascii=False, indent=2, sort_keys=True), "```", ""]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("audit"); parser.add_argument("--json", dest="json_path", default=""); parser.add_argument("--markdown", dest="md_path", default=""); args = parser.parse_args()
    audit = json.loads(Path(args.audit).read_text(encoding="utf-8")); result = certify(audit)
    if args.json_path:
        p = Path(args.json_path); p.parent.mkdir(parents=True, exist_ok=True); p.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    text = markdown(result, audit)
    if args.md_path:
        p = Path(args.md_path); p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text, encoding="utf-8")
    print(text)
    if not result["certified"]: raise SystemExit(1)


if __name__ == "__main__": main()
