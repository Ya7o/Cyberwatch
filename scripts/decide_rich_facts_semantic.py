#!/usr/bin/env python3
"""Decide whether an editorial source needs semantic rich-facts fallback."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cyberwatch.rich_facts_policy import semantic_decision


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("report")
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", default="")
    parser.add_argument("--github-output", default="")
    args = parser.parse_args()

    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    decision = semantic_decision(report, args.source)
    text = json.dumps(decision, ensure_ascii=False, indent=2, sort_keys=True)
    print(text)

    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    if args.github_output:
        with Path(args.github_output).open("a", encoding="utf-8") as handle:
            handle.write(f"use_llm={'true' if decision['use_llm'] else 'false'}\n")
            handle.write(f"reason={decision['reason']}\n")


if __name__ == "__main__":
    main()
