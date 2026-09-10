"""Copy the public HTML regression evidence and minimal dedup examples."""
from pathlib import Path
import json
import shutil

root = Path(__file__).resolve().parents[1]
audit = root / "audit/sector_dedup_2026-09-06"
out = root / "tests/fixtures/editorial_20260906"
out.mkdir(parents=True, exist_ok=True)
for item in ("ITM-7a872ed42e894347", "ITM-909b1b6129a81f63"):
    shutil.copyfile(audit / "sources" / f"{item}.html", out / f"{item}.html")
evidence = json.loads((audit / "local_evidence.json").read_text())
ids = {i for pair in evidence["pairs"] for i in (pair["left"], pair["right"])}
columns = {"Item_ID", "Summary", "Affected_Count", "Affected_Unit", "Affected_Count_Raw",
           "Threat_Actor", "Claim_Status", "Impact", "Victim_Website"}
payload = [{"item": row["item"], "facts": {k: v for k, v in row["facts"].items() if k in columns}}
           for row in evidence["targets"] if row["item"]["Item_ID"] in ids]
(out / "dedup_pairs.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
