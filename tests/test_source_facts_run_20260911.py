"""Collecte `RUN-20260911T171856` : réponses et contextes figés, rejoués sans réseau.

Chaque cas fixe une décision du validateur : ce qui était refusé à tort est
désormais accepté, ce qui était refusé à raison le reste, sous un motif exact.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberwatch import runner_source_facts, source_facts_ai as sfa, source_facts_retry
from cyberwatch.collectors.base import RawEntry
from cyberwatch.headline import is_publishable_for_organisation
from cyberwatch.model import Item
from cyberwatch.source_facts_ai_activity import normalize_activity, rejection_kind
from cyberwatch.source_facts_ai_contract import MAX_EVIDENCE_CHARS
from cyberwatch.source_facts_ai_normalize import (
    _grounded,
    _normalize_summary,
    field_rejection_reason,
)

FIXTURE = (Path(__file__).parent / "fixtures" / "source_facts_20260911"
           / "run_20260911T171856.json")
BREVO = "ITM-c9f092781992098e"
AQUALTER_SUMMARY = "ITM-e1e3ecdb12ce1f80"
AQUALTER_ACTIVITY = "ITM-f4e4e11cbcc11b38"
JOIGNY_RECOMPOSED = "ITM-1764b17f2c4b5c48"
JOIGNY_TOO_LONG = "ITM-8e1b34e80f9a2eb7"


def _case(item_id: str) -> dict:
    cases = json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]
    return next(case for case in cases if case["item_id"] == item_id)


def _configure(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    monkeypatch.setenv("SOURCE_FACTS_AI_STATS_PATH", str(tmp_path / "stats.json"))
    monkeypatch.setenv("SOURCE_FACTS_RETRY_QUEUE_PATH", str(tmp_path / "retry.json"))
    sfa.reset_runtime_for_tests()


def _payload(output: dict) -> dict:
    return {"output_text": json.dumps(output, ensure_ascii=False),
            "usage": {"input_tokens": 100, "output_tokens": 50}}


def _empty_output(body: dict, **values) -> dict:
    result = {}
    for field in body["text"]["format"]["schema"]["properties"]:
        empty = [] if field in {"data_types", "incident_summary"} else {
            "value": "", "confidence": 0.0, "evidence": ""}
        result[field] = values.get(field, empty)
    return result


# --- Brevo : activité et headline refusées à tort ---------------------------

def test_brevo_l_activite_decrite_n_est_plus_attribuee_a_un_tiers():
    """« relations clients » décrit l'offre de Brevo, pas un client de Brevo."""
    case = _case(BREVO)
    assert case["recorded_rejections"]["activity_description"] == "ACTIVITY_THIRD_PARTY"
    result, reasons = normalize_activity(case["proposal"], case["context"], case["organisation"])
    assert result["activity_description"]["evidence"].startswith("Brevo fournit aux entreprises")
    assert result["activity_sector_match"]["value"] == "Numérique / Technologie"
    assert "activity_description" not in reasons


def test_brevo_la_headline_avec_deux_points_est_acceptee():
    case = _case(BREVO)
    summary = case["proposal"]["summary"]
    assert summary["value"].startswith("Brevo: 138 comptes clients accessibles")
    assert _normalize_summary(summary, case["context"], case["organisation"]) is not None


def test_brevo_le_titre_de_l_article_devient_un_repli_publiable():
    case = _case(BREVO)
    title = ("Brevo : 138 comptes compromis, une vaste campagne de phishing frappe "
             "Trezor et CoinTracking")
    assert title in case["context"]
    assert is_publishable_for_organisation(title, case["organisation"])


# --- Aqualter : la limite de preuve reste appliquée -------------------------

def test_aqualter_une_preuve_de_316_caracteres_reste_rejetee():
    case = _case(AQUALTER_SUMMARY)
    summary = case["proposal"]["summary"]
    assert len(summary["evidence"]) > MAX_EVIDENCE_CHARS
    assert _normalize_summary(summary, case["context"], case["organisation"]) is None
    for field in ("summary", "threat_candidate"):
        reason = field_rejection_reason(field, case["proposal"], case["context"],
                                        case["organisation"])
        assert reason == "EVIDENCE_TOO_LONG"
        assert rejection_kind(reason) == "EVIDENCE_TOO_LONG"


def test_aqualter_une_activite_prouvee_par_352_caracteres_reste_rejetee():
    case = _case(AQUALTER_ACTIVITY)
    result, reasons = normalize_activity(case["proposal"], case["context"], case["organisation"])
    assert result == {}
    assert reasons["activity_description"] == "EVIDENCE_TOO_LONG"


def test_aqualter_la_reponse_rejouee_enregistre_le_motif_exact(monkeypatch, tmp_path):
    """Trace, cache et file portent le motif du validateur, pas un fourre-tout."""
    _configure(monkeypatch, tmp_path)
    case = _case(AQUALTER_SUMMARY)
    item = Item(Item_ID=case["item_id"], Source_ID=case["source_id"], URL=case["url"],
                Organisation_Raw=case["organisation"], Published_Date="2026-09-11")
    entry = RawEntry(title="Aqualter", content=case["context"], url=case["url"],
                     organisation=case["organisation"])
    runtime = sfa._runtime()
    monkeypatch.setattr(sfa, "_post_openai", lambda *_: _payload(case["proposal"]))
    normalized, completed = sfa._perform_request(
        item, entry, case["context"], set(case["requested_fields"]), runtime, "k")
    assert completed and "summary" not in normalized
    event = runtime.trace_events[-1]
    assert event["rejections"]["summary"] == "EVIDENCE_TOO_LONG"
    assert event["rejection_kinds"]["summary"] == "EVIDENCE_TOO_LONG"
    assert runtime.cache["k"]["fields"]["summary"]["rejection_reason"] == "EVIDENCE_TOO_LONG"


# --- Joigny : citation recomposée, rejet maintenu, reprise ciblée -----------

JOIGNY_A = ("La Ville de Joigny et la Communauté de communes du Jovinien, dans l’Yonne, "
            "indiquent avoir repoussé 268 795 tentatives d’attaques informatiques en "
            "seulement une semaine.")
JOIGNY_B = "Les attaques ont notamment ciblé des équipements réseau de la collectivité."


def test_joigny_une_citation_recollee_reste_rejetee():
    case = _case(JOIGNY_RECOMPOSED)
    evidence = case["proposal"]["summary"]["evidence"]
    # A et C sont recollés alors que B les sépare dans l'article.
    assert evidence.startswith(JOIGNY_A) and JOIGNY_B not in evidence
    assert JOIGNY_B in case["context"]
    assert not _grounded(evidence, case["context"])
    assert field_rejection_reason("summary", case["proposal"], case["context"],
                                  case["organisation"]) == "EVIDENCE_NOT_GROUNDED"
    assert _grounded(JOIGNY_A, case["context"])


def test_joigny_une_headline_trop_longue_est_nommee():
    case = _case(JOIGNY_TOO_LONG)
    reason = field_rejection_reason("summary", case["proposal"], case["context"],
                                    case["organisation"])
    assert reason == "HEADLINE_TOO_LONG"
    assert rejection_kind(reason) == "HEADLINE_VALIDATION"


def test_joigny_la_reprise_ne_redemande_que_summary_avec_une_citation_continue(
        monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    case = _case(JOIGNY_RECOMPOSED)
    item = Item(Item_ID=case["item_id"], Source_ID=case["source_id"], URL=case["url"],
                Organisation_Raw=case["organisation"], Published_Date="2026-09-11")
    entry = RawEntry(title="Joigny", content=case["context"], url=case["url"],
                     organisation=case["organisation"], published="2026-09-11")
    recomposed = case["proposal"]["summary"]
    continuous = {**recomposed, "evidence": JOIGNY_A}
    bodies: list[dict] = []

    def fake_post(body, _runtime):
        bodies.append(body)
        return _payload(_empty_output(body, summary=recomposed if len(bodies) == 1 else continuous))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)

    sfa.enrich(item, entry)
    assert sfa.field_statuses(item, entry)["summary"] == "miss"
    [row] = source_facts_retry.load()
    assert row["pending_fields"] == ["summary"]
    assert row["field_reasons"] == {"summary": "EVIDENCE_NOT_GROUNDED"}
    assert "Reprise ciblée" not in bodies[0]["input"][1]["content"]

    _, stats = runner_source_facts.retry_pending(source_facts_retry.load())
    assert stats["attempted"] == 1
    retry = bodies[-1]
    # Seul summary est redemandé, avec la consigne propre à son motif.
    assert list(retry["text"]["format"]["schema"]["properties"]) == ["summary"]
    prompt = retry["input"][1]["content"]
    assert "=== Reprise ciblée ===" in prompt
    assert "- summary : " in prompt and "citation continue" in prompt
    assert "ne fusionne jamais deux passages" in prompt
    assert sfa._runtime().trace_events[-1]["retry_reasons"] == {"summary": "EVIDENCE_NOT_GROUNDED"}

    assert sfa.field_statuses(item, entry)["summary"] == "accepted"
    assert source_facts_retry.load() == []


# --- Observabilité de la file -----------------------------------------------

def _row(key, pending, reasons, reason="SEMANTIC_MISS", exhausted=None):
    return {"key": key, "pending_fields": pending, "field_reasons": reasons,
            "reason": reason, "exhausted_fields": exhausted or {}}


def test_la_file_se_decompte_par_dossier_champ_motif_et_famille():
    entries = [
        _row("joigny", ["summary"], {"summary": "EVIDENCE_NOT_GROUNDED"}),
        _row("aqualter", ["summary"], {"summary": "EVIDENCE_TOO_LONG"}),
        _row("brevo", ["activity_description", "activity_sector_match", "summary"],
             {"activity_description": "ACTIVITY_THIRD_PARTY",
              "activity_sector_match": "NO_VALID_ACTIVITY_PAIR",
              "summary": "HEADLINE_LIST_OR_PREFIX"}, reason="SEMANTIC_REJECTED"),
        # Une panne ne laisse aucun motif par champ : c'est son motif de mise en file.
        _row("panne", ["incident_summary"], {}, reason="TECHNICAL_FAILURE"),
        _row("epuise", [], {}, exhausted={"activity_description": {"reason": "ACTIVITY_NOT_DESCRIBED"}}),
    ]
    counts = source_facts_retry.summary(entries)
    assert counts["dossiers"] == 5
    assert counts["dossiers_pending"] == 4
    assert counts["pending_fields"] == 6
    assert counts["exhausted_fields"] == 1
    assert counts["by_field"]["summary"] == 3
    assert counts["by_reason"] == {
        "ACTIVITY_NOT_DESCRIBED": 1, "ACTIVITY_THIRD_PARTY": 1, "EVIDENCE_NOT_GROUNDED": 1,
        "EVIDENCE_TOO_LONG": 1, "HEADLINE_LIST_OR_PREFIX": 1, "NO_VALID_ACTIVITY_PAIR": 1,
        "TECHNICAL_FAILURE": 1,
    }
    assert counts["by_kind"] == {
        "ACTIVITY_NOT_DESCRIBED": 2, "EVIDENCE_NOT_FOUND": 1, "EVIDENCE_TOO_LONG": 1,
        "HEADLINE_VALIDATION": 1, "NOT_PROCESSED": 1, "THIRD_PARTY_ACTIVITY": 1,
    }


@pytest.mark.parametrize("field,reason,kind", [
    ("summary", "EMPTY_OR_REJECTED_BY_VALIDATOR", "UNCLASSIFIED"),  # fourre-tout d'avant
    ("summary", "", "UNCLASSIFIED"),
    ("impact", "MOTIF_INCONNU", "UNCLASSIFIED"),
    ("threat_candidate", "CONFIDENCE_REJECTED", "LOW_CONFIDENCE"),
    ("activity_description", "CONFIDENCE_REJECTED", "ACTIVITY_NOT_DESCRIBED"),
])
def test_la_file_ne_prete_pas_a_un_champ_une_famille_qui_n_est_pas_la_sienne(field, reason, kind):
    counts = source_facts_retry.summary([_row("k", [field], {field: reason} if reason else {},
                                              reason="")])
    assert counts["by_kind"] == {kind: 1}


def test_joigny_la_trace_nomme_chaque_refus_dans_sa_propre_famille(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    case = _case(JOIGNY_TOO_LONG)
    item = Item(Item_ID=case["item_id"], Source_ID=case["source_id"], URL=case["url"],
                Organisation_Raw=case["organisation"], Published_Date="2026-09-11")
    entry = RawEntry(title="Joigny", content=case["context"], url=case["url"])
    runtime = sfa._runtime()
    monkeypatch.setattr(sfa, "_post_openai", lambda *_: _payload(case["proposal"]))
    sfa._perform_request(item, entry, case["context"], set(case["requested_fields"]), runtime, "k")
    event = runtime.trace_events[-1]
    assert event["rejections"] == {"summary": "HEADLINE_TOO_LONG",
                                   "threat_candidate": "CONFIDENCE_REJECTED"}
    assert event["rejection_kinds"] == {"summary": "HEADLINE_VALIDATION",
                                        "threat_candidate": "LOW_CONFIDENCE"}


def test_l_archive_et_le_rapport_exposent_le_detail_de_la_file(monkeypatch, tmp_path):
    from cyberwatch import qualification

    monkeypatch.setenv("SOURCE_FACTS_RETRY_QUEUE_PATH", str(tmp_path / "retry.json"))
    item = Item(Item_ID="ITM-1", Source_ID="FRENCHBREACHES", Organisation_Raw="Exemple SA")
    entry = RawEntry(title="Exemple SA", content="Incident")
    source_facts_retry.enqueue(item, entry, {"summary"}, "SEMANTIC_MISS",
                               reasons={"summary": "EVIDENCE_NOT_GROUNDED"})
    path = source_facts_retry.archive("RUN-FILE")
    archived = json.loads(path.read_text(encoding="utf-8"))
    assert archived["summary"]["pending_fields"] == 1
    assert archived["summary"]["by_reason"] == {"EVIDENCE_NOT_GROUNDED": 1}

    (path.parent / "source_facts_ai_usage.json").write_text("{}", encoding="utf-8")
    report = qualification.markdown_report(qualification.load_run("RUN-FILE", tmp_path))
    assert "### File de reprise" in report
    assert "| EVIDENCE_NOT_GROUNDED | EVIDENCE_NOT_FOUND | 1 |" in report
