from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement, got {count}")
    target.write_text(text.replace(old, new), encoding="utf-8")


replace_once(
    "cyberwatch/source_facts.py",
    '''def _finalize(fact: dict, entry: RawEntry, evidence: dict) -> dict | None:
    if not _has_content(fact):
        return None
    fact["Evidence_JSON"] = _dumps_json(evidence)
    metadata = dict(entry.source_metadata or {})
    if fact.get("Source_ID") in source_facts_ai.TARGET_SOURCES:
        # L'empreinte permet de distinguer une abstention sur le même article
        # d'une abstention après correction réelle du contenu source.
        metadata["_source_facts_content_hash"] = source_facts_ai.content_hash(entry)
    if metadata:
        fact["Source_Metadata_JSON"] = _dumps_json(metadata)
    return fact
''',
    '''def _finalize(fact: dict, entry: RawEntry, evidence: dict) -> dict | None:
    if not _has_content(fact):
        return None
    fact["Evidence_JSON"] = _dumps_json(evidence)
    semantic_status = fact.pop("_Semantic_Refresh_Status", None)
    metadata = dict(entry.source_metadata or {})
    if fact.get("Source_ID") in source_facts_ai.TARGET_SOURCES:
        # Ces marqueurs restent dans le metadata auxiliaire, jamais dans le
        # schéma public SOURCE_FACT_COLUMNS.
        metadata["_source_facts_content_hash"] = source_facts_ai.content_hash(entry)
        if isinstance(semantic_status, dict) and semantic_status:
            metadata["_source_facts_semantic_status"] = semantic_status
    if metadata:
        fact["Source_Metadata_JSON"] = _dumps_json(metadata)
    return fact
''',
)

replace_once(
    "cyberwatch/source_facts.py",
    '''        refresh_status = new.get("_Semantic_Refresh_Status")
        refresh_status = refresh_status if isinstance(refresh_status, dict) else {}
''',
    '''        refresh_status = (
            new_meta.get("_source_facts_semantic_status")
            if isinstance(new_meta, dict) else {}
        )
        refresh_status = refresh_status if isinstance(refresh_status, dict) else {}
''',
)

replace_once(
    "tests/test_source_facts_quality_telemetry.py",
    '''def _row(content_hash: str, *, summary: str = "", impact: str = "", statuses=None) -> dict:
    row = {
        "Item_ID": "ITM-merge-quality",
        "Source_ID": "CYBERATTAQUE_ORG",
        "Summary": summary,
        "Impact": impact,
        "Source_Metadata_JSON": json.dumps({"_source_facts_content_hash": content_hash}),
        "Evidence_JSON": json.dumps({
            **({"Summary": "preuve synthèse"} if summary else {}),
            **({"Impact": "preuve impact"} if impact else {}),
        }),
    }
    if statuses is not None:
        row["_Semantic_Refresh_Status"] = statuses
    return row
''',
    '''def _row(content_hash: str, *, summary: str = "", impact: str = "", statuses=None) -> dict:
    metadata = {"_source_facts_content_hash": content_hash}
    if statuses is not None:
        metadata["_source_facts_semantic_status"] = statuses
    return {
        "Item_ID": "ITM-merge-quality",
        "Source_ID": "CYBERATTAQUE_ORG",
        "Summary": summary,
        "Impact": impact,
        "Source_Metadata_JSON": json.dumps(metadata),
        "Evidence_JSON": json.dumps({
            **({"Summary": "preuve synthèse"} if summary else {}),
            **({"Impact": "preuve impact"} if impact else {}),
        }),
    }
''',
)

print("SourceFacts transient state kept inside metadata")
