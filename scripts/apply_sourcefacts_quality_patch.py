from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise SystemExit(f"replacement mismatch {path}: expected 1, got {text.count(old)}")
    target.write_text(text.replace(old, new), encoding="utf-8")


# ---------------------------------------------------------------------------
# SourceFacts AI: truthful cache telemetry + public cache state helpers.
# ---------------------------------------------------------------------------
replace_once(
    "cyberwatch/source_facts_ai.py",
    '''        self.cache_hits = 0
        self.field_cache_hits = 0
        self.legacy_field_cache_hits = 0
        self.fields_invalidated = 0
''',
    '''        self.cache_hits = 0
        # field_cache_hits reste le compteur agrégé historique. Les compteurs
        # suivants distinguent désormais une valeur réellement réutilisée
        # d'une abstention mémorisée, afin de ne plus présenter les deux comme
        # un même "cache hit" dans les audits de rebuild.
        self.field_cache_hits = 0
        self.accepted_field_cache_hits = 0
        self.abstained_field_cache_hits = 0
        self.legacy_null_migrations = 0
        self.semantic_first_misses = 0
        self.semantic_retries = 0
        self.semantic_recovered_on_retry = 0
        self.semantic_new_abstentions = 0
        self.legacy_field_cache_hits = 0
        self.fields_invalidated = 0
''',
)

replace_once(
    "cyberwatch/source_facts_ai.py",
    '''            "cache_hits": self.cache_hits,
            "field_cache_hits": self.field_cache_hits,
            "legacy_field_cache_hits": self.legacy_field_cache_hits,
            "fields_invalidated": self.fields_invalidated,
''',
    '''            "cache_hits": self.cache_hits,
            "field_cache_hits": self.field_cache_hits,
            "accepted_field_cache_hits": self.accepted_field_cache_hits,
            "abstained_field_cache_hits": self.abstained_field_cache_hits,
            "legacy_null_migrations": self.legacy_null_migrations,
            "semantic_first_misses": self.semantic_first_misses,
            "semantic_retries": self.semantic_retries,
            "semantic_recovered_on_retry": self.semantic_recovered_on_retry,
            "semantic_new_abstentions": self.semantic_new_abstentions,
            "legacy_field_cache_hits": self.legacy_field_cache_hits,
            "fields_invalidated": self.fields_invalidated,
''',
)

replace_once(
    "cyberwatch/source_facts_ai.py",
    '''def _content_hash(entry: RawEntry) -> str:
    return hashlib.sha256(_full_context(entry).encode("utf-8")).hexdigest()


def _truncate_context(context: str, max_chars: int) -> str:
''',
    '''def _content_hash(entry: RawEntry) -> str:
    return hashlib.sha256(_full_context(entry).encode("utf-8")).hexdigest()


def content_hash(entry: RawEntry) -> str:
    """Empreinte publique de l'entrée utilisée pour la cohérence SourceFacts."""
    return _content_hash(entry)


def field_statuses(item: Item, entry: RawEntry) -> dict[str, str]:
    """État courant des champs du cache pour cette version exacte du contenu.

    Une panne technique n'invente aucun état : si un premier miss existait, il
    reste ``miss``. Seules deux réponses sémantiques vides peuvent donc faire
    apparaître ``abstained`` et autoriser le nettoyage d'un fait devenu obsolète.
    """
    if item.Source_ID not in TARGET_SOURCES:
        return {}
    runtime = _runtime()
    key = _cache_item_key(item, entry, runtime)
    cache_entry = runtime.cache.get(key)
    if not isinstance(cache_entry, dict) or not isinstance(cache_entry.get("fields"), dict):
        return {}
    result: dict[str, str] = {}
    for field, cached in cache_entry["fields"].items():
        if field not in FIELD_VERSIONS or not isinstance(cached, dict):
            continue
        status = str(cached.get("status") or "").strip().lower()
        if status in {"accepted", "miss", "abstained"}:
            result[field] = status
    return result


def _truncate_context(context: str, max_chars: int) -> str:
''',
)

replace_once(
    "cyberwatch/source_facts_ai.py",
    '''            else:
                status = "miss"
                cached["status"] = status
                cached["misses"] = max(1, _cache_miss_count(cached))

        if status == "miss":
''',
    '''            else:
                status = "miss"
                cached["status"] = status
                cached["misses"] = max(1, _cache_miss_count(cached))
                runtime.legacy_null_migrations += 1

        if status == "miss":
''',
)

replace_once(
    "cyberwatch/source_facts_ai.py",
    '''        if status == "abstained":
            satisfied.add(field)
            runtime.field_cache_hits += 1
            continue

        if status != "accepted" or not _cache_value_present(value):
''',
    '''        if status == "abstained":
            satisfied.add(field)
            runtime.field_cache_hits += 1
            runtime.abstained_field_cache_hits += 1
            continue

        if status != "accepted" or not _cache_value_present(value):
''',
)

replace_once(
    "cyberwatch/source_facts_ai.py",
    '''        satisfied.add(field)
        runtime.field_cache_hits += 1
        result[field] = value
    return result, satisfied


def _store_field_cache(runtime: _Runtime, key: str, item: Item, entry: RawEntry, fields: set[str], normalized: dict) -> None:
    target = _cache_entry(runtime, key, item, entry)["fields"]
    for field in fields:
        if field in normalized and _cache_value_present(normalized[field]):
            target[field] = {
                "version": FIELD_VERSIONS[field],
                "status": "accepted",
                "misses": 0,
                "value": normalized[field],
            }
            continue
        previous = target.get(field)
        misses = _cache_miss_count(previous) + 1 if isinstance(previous, dict) else 1
        target[field] = {
            "version": FIELD_VERSIONS[field],
            "status": "abstained" if misses >= MAX_FIELD_MISSES else "miss",
            "misses": misses,
            "value": None,
        }
''',
    '''        satisfied.add(field)
        runtime.field_cache_hits += 1
        runtime.accepted_field_cache_hits += 1
        result[field] = value
    return result, satisfied


def _store_field_cache(runtime: _Runtime, key: str, item: Item, entry: RawEntry, fields: set[str], normalized: dict) -> None:
    target = _cache_entry(runtime, key, item, entry)["fields"]
    for field in fields:
        previous = target.get(field)
        previous_status = (
            str(previous.get("status") or "").strip().lower()
            if isinstance(previous, dict) else ""
        )
        previous_misses = _cache_miss_count(previous) if isinstance(previous, dict) else 0
        is_retry = previous_status == "miss" and previous_misses > 0
        if is_retry:
            runtime.semantic_retries += 1

        if field in normalized and _cache_value_present(normalized[field]):
            if is_retry:
                runtime.semantic_recovered_on_retry += 1
            target[field] = {
                "version": FIELD_VERSIONS[field],
                "status": "accepted",
                "misses": 0,
                "value": normalized[field],
            }
            continue

        misses = previous_misses + 1 if isinstance(previous, dict) else 1
        next_status = "abstained" if misses >= MAX_FIELD_MISSES else "miss"
        if misses == 1:
            runtime.semantic_first_misses += 1
        if next_status == "abstained" and previous_status != "abstained":
            runtime.semantic_new_abstentions += 1
        target[field] = {
            "version": FIELD_VERSIONS[field],
            "status": next_status,
            "misses": misses,
            "value": None,
        }
''',
)

# ---------------------------------------------------------------------------
# SourceFacts rows: content-aware stale-data safety + BLF certainty wording.
# ---------------------------------------------------------------------------
replace_once(
    "cyberwatch/source_facts.py",
    '''def _finalize(fact: dict, entry: RawEntry, evidence: dict) -> dict | None:
    if not _has_content(fact):
        return None
    fact["Evidence_JSON"] = _dumps_json(evidence)
    if entry.source_metadata:
        fact["Source_Metadata_JSON"] = _dumps_json(entry.source_metadata)
    return fact


_BLF_STATUS = {"🟢": "confirmed", "🟠": "claimed", "🔴": "unconfirmed"}
''',
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


def _apply_blf_summary_certainty(fact: dict) -> None:
    """Évite de présenter une revendication BLF comme un fait confirmé."""
    summary = str(fact.get("Summary") or "").strip()
    status = str(fact.get("Claim_Status") or "").strip()
    if not summary or status == "confirmed":
        return
    replacements = {
        "claimed": (
            ("Données concernées :", "Données revendiquées selon BonjourLaFuite :"),
            ("Éléments documentés :", "Éléments revendiqués selon BonjourLaFuite :"),
        ),
        "unconfirmed": (
            ("Données concernées :", "Données signalées mais non confirmées :"),
            ("Éléments documentés :", "Éléments signalés mais non confirmés :"),
        ),
    }
    for prefix, replacement in replacements.get(status, ()):
        if summary.startswith(prefix):
            fact["Summary"] = replacement + summary[len(prefix):]
            return


_BLF_STATUS = {"🟢": "confirmed", "🟠": "claimed", "🔴": "unconfirmed"}
''',
)

replace_once(
    "cyberwatch/source_facts.py",
    '''    _derive_summary(fact, evidence)

    source_urls = meta.get("source_urls") or []
''',
    '''    _derive_summary(fact, evidence)
    _apply_blf_summary_certainty(fact)

    source_urls = meta.get("source_urls") or []
''',
)

# Both AI-backed extractors record only transient status metadata; the stable
# input hash itself is persisted by _finalize in Source_Metadata_JSON.
old_ai_line = '''    ai_result = source_facts_ai.enrich(item, entry) or {}

'''
new_ai_line = '''    ai_result = source_facts_ai.enrich(item, entry) or {}
    fact["_Semantic_Refresh_Status"] = source_facts_ai.field_statuses(item, entry)

'''
source_path = ROOT / "cyberwatch/source_facts.py"
source_text = source_path.read_text(encoding="utf-8")
if source_text.count(old_ai_line) != 2:
    raise SystemExit(f"expected 2 AI extractor sites, got {source_text.count(old_ai_line)}")
source_path.write_text(source_text.replace(old_ai_line, new_ai_line), encoding="utf-8")

replace_once(
    "cyberwatch/source_facts.py",
    '''    def merge_row(old: dict, new: dict) -> dict:
        merged = dict(old)
        old_evidence = _loads_json(str(old.get("Evidence_JSON") or ""))
        new_evidence = _loads_json(str(new.get("Evidence_JSON") or ""))
        evidence = dict(old_evidence) if isinstance(old_evidence, dict) else {}
        if isinstance(new_evidence, dict):
            for field, proof in new_evidence.items():
                if field in refreshable and new.get(field, "") in (None, ""):
                    continue
                if field in refreshable:
                    evidence.pop(field, None)
                evidence[field] = proof
        for column in SOURCE_FACT_COLUMNS:
            if column == "Evidence_JSON":
                continue
            value = new.get(column, "")
            if column in refreshable:
                if value not in (None, ""):
                    merged[column] = value
            elif column in base:
                if value not in (None, ""):
                    merged[column] = value
            elif value not in (None, ""):
                merged[column] = value
        merged["Evidence_JSON"] = _dumps_json(evidence)
        return merged
''',
    '''    ai_field_for_column = {
        "Summary": "summary",
        "Initial_Access": "initial_access",
        "Attack_Flow_JSON": "attack_flow",
        "Impact": "impact",
    }

    def merge_row(old: dict, new: dict) -> dict:
        merged = dict(old)
        old_evidence = _loads_json(str(old.get("Evidence_JSON") or ""))
        new_evidence = _loads_json(str(new.get("Evidence_JSON") or ""))
        evidence = dict(old_evidence) if isinstance(old_evidence, dict) else {}
        old_meta = _loads_json(str(old.get("Source_Metadata_JSON") or ""))
        new_meta = _loads_json(str(new.get("Source_Metadata_JSON") or ""))
        old_hash = str(old_meta.get("_source_facts_content_hash") or "") if isinstance(old_meta, dict) else ""
        new_hash = str(new_meta.get("_source_facts_content_hash") or "") if isinstance(new_meta, dict) else ""
        content_changed = bool(old_hash and new_hash and old_hash != new_hash)
        refresh_status = new.get("_Semantic_Refresh_Status")
        refresh_status = refresh_status if isinstance(refresh_status, dict) else {}

        def should_clear(column: str) -> bool:
            # Un premier miss peut être une abstention sémantique transitoire ;
            # une panne technique ne modifie pas le cache. On ne retire donc un
            # ancien fait qu'après deux abstentions sémantiques sur un contenu
            # effectivement différent.
            field = ai_field_for_column.get(column, "")
            return (
                content_changed
                and field
                and refresh_status.get(field) == "abstained"
                and new.get(column, "") in (None, "")
            )

        if isinstance(new_evidence, dict):
            for field, proof in new_evidence.items():
                if field in refreshable and new.get(field, "") in (None, ""):
                    if should_clear(field):
                        evidence.pop(field, None)
                    continue
                if field in refreshable:
                    evidence.pop(field, None)
                evidence[field] = proof
        for column in SOURCE_FACT_COLUMNS:
            if column == "Evidence_JSON":
                continue
            value = new.get(column, "")
            if column in refreshable:
                if value not in (None, ""):
                    merged[column] = value
                elif should_clear(column):
                    merged[column] = ""
                    evidence.pop(column, None)
            elif column in base:
                if value not in (None, ""):
                    merged[column] = value
            elif value not in (None, ""):
                merged[column] = value
        merged["Evidence_JSON"] = _dumps_json(evidence)
        return merged
''',
)

# ---------------------------------------------------------------------------
# Structured per-source telemetry in RUN_SOURCES.
# ---------------------------------------------------------------------------
replace_once(
    "cyberwatch/status.py",
    '''    source_facts_llm_duration_seconds: float = 0.0
    source_facts_llm_calls: int = 0
    source_facts_llm_cost_usd: float = 0.0
    other_processing_duration_seconds: float = 0.0
''',
    '''    source_facts_llm_duration_seconds: float = 0.0
    source_facts_llm_calls: int = 0
    source_facts_llm_cost_usd: float = 0.0
    source_facts_accepted_cache_hits: int = 0
    source_facts_abstained_cache_hits: int = 0
    source_facts_legacy_null_migrations: int = 0
    source_facts_semantic_first_misses: int = 0
    source_facts_semantic_retries: int = 0
    source_facts_recovered_on_retry: int = 0
    source_facts_new_abstentions: int = 0
    other_processing_duration_seconds: float = 0.0
''',
)

replace_once(
    "cyberwatch/model.py",
    '''    "SourceFacts_LLM_Duration_s",
    "SourceFacts_LLM_Calls",
    "SourceFacts_LLM_Cost_USD",
    "Other_Processing_Duration_s",
''',
    '''    "SourceFacts_LLM_Duration_s",
    "SourceFacts_LLM_Calls",
    "SourceFacts_LLM_Cost_USD",
    "SourceFacts_Accepted_Cache_Hits",
    "SourceFacts_Abstained_Cache_Hits",
    "SourceFacts_Legacy_Null_Migrations",
    "SourceFacts_Semantic_First_Misses",
    "SourceFacts_Semantic_Retries",
    "SourceFacts_Recovered_On_Retry",
    "SourceFacts_New_Abstentions",
    "Other_Processing_Duration_s",
''',
)

replace_once(
    "cyberwatch/runner.py",
    '''    outcome.source_facts_llm_cost_usd = round(max(
        0.0,
        float(source_facts_after.get("estimated_cost_usd", 0.0))
        - float(source_facts_before.get("estimated_cost_usd", 0.0)),
    ), 6)
    measured_external = (
''',
    '''    outcome.source_facts_llm_cost_usd = round(max(
        0.0,
        float(source_facts_after.get("estimated_cost_usd", 0.0))
        - float(source_facts_before.get("estimated_cost_usd", 0.0)),
    ), 6)

    def sf_delta(key: str) -> int:
        return max(
            0,
            int(source_facts_after.get(key, 0)) - int(source_facts_before.get(key, 0)),
        )

    outcome.source_facts_accepted_cache_hits = sf_delta("accepted_field_cache_hits")
    outcome.source_facts_abstained_cache_hits = sf_delta("abstained_field_cache_hits")
    outcome.source_facts_legacy_null_migrations = sf_delta("legacy_null_migrations")
    outcome.source_facts_semantic_first_misses = sf_delta("semantic_first_misses")
    outcome.source_facts_semantic_retries = sf_delta("semantic_retries")
    outcome.source_facts_recovered_on_retry = sf_delta("semantic_recovered_on_retry")
    outcome.source_facts_new_abstentions = sf_delta("semantic_new_abstentions")
    measured_external = (
''',
)

replace_once(
    "cyberwatch/runner.py",
    '''                f"sf-llm={outcome.source_facts_llm_duration_seconds:.1f}s/{outcome.source_facts_llm_calls} "
                f"other={outcome.other_processing_duration_seconds:.1f}s"
''',
    '''                f"sf-llm={outcome.source_facts_llm_duration_seconds:.1f}s/{outcome.source_facts_llm_calls} "
                f"sf-cache=accepted:{outcome.source_facts_accepted_cache_hits}/"
                f"abstained:{outcome.source_facts_abstained_cache_hits} "
                f"sf-retry={outcome.source_facts_semantic_retries}/"
                f"recovered:{outcome.source_facts_recovered_on_retry}/"
                f"new-abstain:{outcome.source_facts_new_abstentions} "
                f"other={outcome.other_processing_duration_seconds:.1f}s"
''',
)

replace_once(
    "cyberwatch/runner.py",
    '''                "SourceFacts_LLM_Duration_s": o.source_facts_llm_duration_seconds,
                "SourceFacts_LLM_Calls": o.source_facts_llm_calls,
                "SourceFacts_LLM_Cost_USD": o.source_facts_llm_cost_usd,
                "Other_Processing_Duration_s": o.other_processing_duration_seconds,
''',
    '''                "SourceFacts_LLM_Duration_s": o.source_facts_llm_duration_seconds,
                "SourceFacts_LLM_Calls": o.source_facts_llm_calls,
                "SourceFacts_LLM_Cost_USD": o.source_facts_llm_cost_usd,
                "SourceFacts_Accepted_Cache_Hits": o.source_facts_accepted_cache_hits,
                "SourceFacts_Abstained_Cache_Hits": o.source_facts_abstained_cache_hits,
                "SourceFacts_Legacy_Null_Migrations": o.source_facts_legacy_null_migrations,
                "SourceFacts_Semantic_First_Misses": o.source_facts_semantic_first_misses,
                "SourceFacts_Semantic_Retries": o.source_facts_semantic_retries,
                "SourceFacts_Recovered_On_Retry": o.source_facts_recovered_on_retry,
                "SourceFacts_New_Abstentions": o.source_facts_new_abstentions,
                "Other_Processing_Duration_s": o.other_processing_duration_seconds,
''',
)

# Keep the standalone performance report immediately useful after a rebuild.
replace_once(
    "scripts/report_source_performance.py",
    '''            f"sf_llm={_num(row,'SourceFacts_LLM_Duration_s'):.1f}s/{row.get('SourceFacts_LLM_Calls') or 0} "
            f"other={_num(row,'Other_Processing_Duration_s'):.1f}s "
            f"llm_cost=${q_cost + sf_cost:.6f}"
''',
    '''            f"sf_llm={_num(row,'SourceFacts_LLM_Duration_s'):.1f}s/{row.get('SourceFacts_LLM_Calls') or 0} "
            f"sf_cache=accepted:{row.get('SourceFacts_Accepted_Cache_Hits') or 0}/"
            f"abstained:{row.get('SourceFacts_Abstained_Cache_Hits') or 0} "
            f"sf_migrate_null={row.get('SourceFacts_Legacy_Null_Migrations') or 0} "
            f"sf_miss={row.get('SourceFacts_Semantic_First_Misses') or 0} "
            f"sf_retry={row.get('SourceFacts_Semantic_Retries') or 0}/"
            f"recovered:{row.get('SourceFacts_Recovered_On_Retry') or 0}/"
            f"new_abstain:{row.get('SourceFacts_New_Abstentions') or 0} "
            f"other={_num(row,'Other_Processing_Duration_s'):.1f}s "
            f"llm_cost=${q_cost + sf_cost:.6f}"
''',
)

# Focused regression coverage.
(ROOT / "tests/test_source_facts_quality_telemetry.py").write_text(r'''from __future__ import annotations

import json

from cyberwatch import source_facts as sf
from cyberwatch import source_facts_ai as sfa
from cyberwatch.collectors.base import RawEntry, SourceSpec
from cyberwatch.model import Item


def _item(source_id: str = "CYBERATTAQUE_ORG") -> Item:
    return Item(
        Item_ID="ITM-quality-telemetry",
        Source_ID=source_id,
        Organisation_Raw="Exemple SA",
        Published_Date="2026-08-18",
    )


def test_bonjourlafuite_claimed_summary_keeps_claim_semantics():
    item = _item("BONJOURLAFUITE")
    spec = SourceSpec(source_id="BONJOURLAFUITE", layer="core", zone="France")
    entry = RawEntry(
        title="Exemple SA",
        source_metadata={
            "claim_status_raw": "🟠",
            "data_types": ["Nom et prénom", "Adresse e-mail", "Téléphone"],
        },
    )
    fact = sf.extract_source_fact(item, entry, spec)
    assert fact is not None
    assert fact["Claim_Status"] == "claimed"
    assert fact["Summary"].startswith("Données revendiquées selon BonjourLaFuite :")


def test_bonjourlafuite_unconfirmed_summary_is_not_affirmative():
    item = _item("BONJOURLAFUITE")
    spec = SourceSpec(source_id="BONJOURLAFUITE", layer="core", zone="France")
    entry = RawEntry(
        title="Exemple SA",
        source_metadata={
            "claim_status_raw": "🔴",
            "data_types": ["Nom et prénom", "Adresse e-mail", "Téléphone"],
        },
    )
    fact = sf.extract_source_fact(item, entry, spec)
    assert fact is not None
    assert fact["Claim_Status"] == "unconfirmed"
    assert fact["Summary"].startswith("Données signalées mais non confirmées :")


def _row(content_hash: str, *, summary: str = "", impact: str = "", statuses=None) -> dict:
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


def test_changed_content_clears_only_confirmed_abstention():
    old = _row("old", summary="Ancienne synthèse.", impact="Ancien impact.")
    new = _row(
        "new",
        statuses={"summary": "abstained", "impact": "miss"},
    )
    merged = sf.merge_source_facts([old], [new])[0]
    assert merged["Summary"] == ""
    assert merged["Impact"] == "Ancien impact."
    evidence = json.loads(merged["Evidence_JSON"])
    assert "Summary" not in evidence
    assert evidence["Impact"] == "preuve impact"


def test_same_content_or_first_miss_never_erases_valid_fact():
    old = _row("same", summary="Synthèse valide.")
    same = _row("same", statuses={"summary": "abstained"})
    assert sf.merge_source_facts([old], [same])[0]["Summary"] == "Synthèse valide."

    changed_first_miss = _row("changed", statuses={"summary": "miss"})
    assert sf.merge_source_facts([old], [changed_first_miss])[0]["Summary"] == "Synthèse valide."


def _configure_runtime(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    monkeypatch.setenv("SOURCE_FACTS_AI_STATS_PATH", str(tmp_path / "stats.json"))
    sfa.reset_runtime_for_tests()
    return sfa._runtime()


def test_cache_telemetry_separates_values_and_abstentions(monkeypatch, tmp_path):
    runtime = _configure_runtime(monkeypatch, tmp_path)
    item = _item()
    entry = RawEntry(title="Exemple", content="Un contenu suffisamment long pour le test de cache sémantique.")
    key = sfa._cache_item_key(item, entry, runtime)
    runtime.cache[key] = {
        "fields": {
            "summary": {"version": sfa.FIELD_VERSIONS["summary"], "status": "accepted", "misses": 0, "value": {"value": "Résumé", "confidence": 0.9, "evidence": "preuve"}},
            "impact": {"version": sfa.FIELD_VERSIONS["impact"], "status": "abstained", "misses": 2, "value": None},
        }
    }
    values, satisfied = sfa._read_field_cache(runtime, key, {"summary", "impact"})
    assert "summary" in values
    assert satisfied == {"summary", "impact"}
    stats = runtime.stats()
    assert stats["accepted_field_cache_hits"] == 1
    assert stats["abstained_field_cache_hits"] == 1
    assert stats["field_cache_hits"] == 2


def test_retry_telemetry_tracks_recovery_and_new_abstention(monkeypatch, tmp_path):
    runtime = _configure_runtime(monkeypatch, tmp_path)
    item = _item()
    entry = RawEntry(title="Exemple", content="Contexte de test")
    key = sfa._cache_item_key(item, entry, runtime)

    sfa._store_field_cache(runtime, key, item, entry, {"summary"}, {})
    assert runtime.semantic_first_misses == 1
    sfa._store_field_cache(
        runtime,
        key,
        item,
        entry,
        {"summary"},
        {"summary": {"value": "Résumé", "confidence": 0.9, "evidence": "preuve"}},
    )
    assert runtime.semantic_retries == 1
    assert runtime.semantic_recovered_on_retry == 1

    sfa._store_field_cache(runtime, key, item, entry, {"impact"}, {})
    sfa._store_field_cache(runtime, key, item, entry, {"impact"}, {})
    assert runtime.semantic_retries == 2
    assert runtime.semantic_new_abstentions == 1
''', encoding="utf-8")

print("SourceFacts quality/telemetry patch applied")
