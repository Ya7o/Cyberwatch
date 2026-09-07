#!/usr/bin/env python3
"""Mesure déterministe de la taille des modules et fonctions Python."""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Finding:
    path: Path
    name: str
    lines: int
    start: int


def python_files() -> list[Path]:
    return sorted((ROOT / "cyberwatch").rglob("*.py"))


def module_findings(limit: int) -> list[Finding]:
    findings = []
    for path in python_files():
        lines = len(path.read_text(encoding="utf-8").splitlines())
        if lines > limit:
            findings.append(Finding(path.relative_to(ROOT), "<module>", lines, 1))
    return sorted(findings, key=lambda row: (-row.lines, str(row.path)))


def function_findings(limit: int) -> list[Finding]:
    findings = []
    for path in python_files():
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            lines = (node.end_lineno or node.lineno) - node.lineno + 1
            if lines > limit:
                findings.append(
                    Finding(path.relative_to(ROOT), node.name, lines, node.lineno)
                )
    return sorted(findings, key=lambda row: (-row.lines, str(row.path), row.start))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-module-lines", type=int, default=1000)
    parser.add_argument("--max-function-lines", type=int, default=100)
    parser.add_argument("--module-budget", type=int, default=0)
    parser.add_argument("--function-budget", type=int, default=0)
    args = parser.parse_args(argv)

    modules = module_findings(args.max_module_lines)
    functions = function_findings(args.max_function_lines)
    for finding in modules:
        print(f"MODULE {finding.path}: {finding.lines} lignes")
    for finding in functions:
        print(
            f"FUNCTION {finding.path}:{finding.start} "
            f"{finding.name}: {finding.lines} lignes"
        )
    if len(modules) > args.module_budget or len(functions) > args.function_budget:
        print(
            f"ÉCHEC — {len(modules)}/{args.module_budget} module(s), "
            f"{len(functions)}/{args.function_budget} fonction(s) hors seuil"
        )
        return 1
    print(
        f"OK — budget respecté : {len(modules)}/{args.module_budget} module(s), "
        f"{len(functions)}/{args.function_budget} fonction(s) hors seuil"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
