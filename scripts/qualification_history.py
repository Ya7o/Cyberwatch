#!/usr/bin/env python3
"""Enregistre une baseline qualification et signale les dérives par source."""
from __future__ import annotations
import argparse, csv, json
from pathlib import Path
from cyberwatch.qualification_history import detect_source_drift, history_rows
FIELDS = ["Run_ID","Recorded_At","Source_ID","Field","Total","Known","Unknown","Coverage_pct","Decisions","Applied","Rejected","Protected"]
def load_history(path):
    if not path.exists(): return []
    with path.open(encoding="utf-8", newline="") as handle: return list(csv.DictReader(handle))
def main():
    parser=argparse.ArgumentParser(); parser.add_argument("report"); parser.add_argument("--run-id",required=True); parser.add_argument("--history",default="data/qualification_history.csv"); parser.add_argument("--check",action="store_true")
    args=parser.parse_args(); path=Path(args.history); old=load_history(path); report=json.loads(Path(args.report).read_text(encoding="utf-8")); current=history_rows(report,run_id=args.run_id); alerts=detect_source_drift(current,old)
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("a",encoding="utf-8",newline="") as handle:
        writer=csv.DictWriter(handle,fieldnames=FIELDS)
        if not old: writer.writeheader()
        writer.writerows(current)
    print(json.dumps({"run_id":args.run_id,"rows":len(current),"drift_alerts":alerts},ensure_ascii=False,indent=2)); return 1 if args.check and alerts else 0
if __name__ == "__main__": raise SystemExit(main())
