#!/usr/bin/env python3
"""Extrait une vue aveugle des incidents Cyberwatch pour créer/revoir le golden set."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch.golden import CANDIDATE_COLUMNS, blind_candidates, group_candidates_round_robin, read_csv, write_csv


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--incidents", default=str(ROOT / "data" / "incidents.csv"))
    parser.add_argument("--output", default=str(ROOT / "bench" / "results" / "golden_candidates.csv"))
    parser.add_argument(
        "--limit",
        type=int,
        default=150,
        help="Nombre maximal de candidats (<=0 = tous). Échantillonnage déterministe équilibré par source.",
    )
    args = parser.parse_args()

    incidents = read_csv(args.incidents)
    rows = blind_candidates(incidents)
    rows = group_candidates_round_robin(rows, limit=args.limit)
    write_csv(args.output, rows, CANDIDATE_COLUMNS)
    print(f"golden_candidates={len(rows)}")
    print(f"output={args.output}")
    print("blind_fields=Incident_ID,Date,Organisation,Organisation_Key,Sources,Source_URLs")


if __name__ == "__main__":
    main()
