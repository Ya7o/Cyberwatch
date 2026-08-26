"""Fallback LLM sur le texte page officielle déjà scrappé (jamais de réseau HTTP)."""
from __future__ import annotations

import json

import pytest

from cyberwatch import config, domain_page_sector as dps, llm_runtime
from cyberwatch import domain_page_sector_llm as dpl


class _Response:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def _payload(data, *, input_tokens=80, output_tokens=15):
    return {
        "status": "completed",
        "output": [{
            "type": "message",
            "content": [{"type": "output_text", "text": json.dumps(data)}],
        }],
        "usage": {
            "input_tokens": input_tokens,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens": output_tokens,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": input_tokens + output_tokens,
        },
    }


def _enable_llm(monkeypatch, fake_post):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(llm_runtime, "_RUNTIME", llm_runtime.LlmRuntime())
    monkeypatch.setattr(llm_runtime.requests, "post", fake_post)


def _row(**overrides):
    row = {
        "Organisation_Key": "klark ai", "Organisation": "Klark.ai",
        "URL": "https://klark.ai/", "Status": dps.STATUS_NO_EVIDENCE,
        "Activity_Description": "", "Activity_Sector_Match": "", "Extraction_Source": "",
        "Page_Title": "Klark", "Page_Description": "Nous aidons les équipes à mieux vendre.",
        "Fetched_At": "2026-08-25T00:00:00+00:00",
    }
    row.update(overrides)
    return row


# --------------------------------------------------------------------------
# Sélection : uniquement du texte déjà fetché, jamais classé
# --------------------------------------------------------------------------


def test_selection_ignore_les_lignes_deja_resolues():
    resolue = _row(Activity_Sector_Match=config.SECTOR_TECH, Extraction_Source="deterministic")
    assert dpl.select_rows_for_llm([resolue]) == []


def test_selection_ignore_les_lignes_jamais_fetchees():
    """Garde d'identité échouée ou page injoignable : rien à ancrer un appel
    LLM dessus — cette fonction ne fait elle-même aucun accès réseau."""
    garde_echouee = _row(Status=dps.STATUS_NO_EVIDENCE, Page_Title="", Page_Description="")
    injoignable = _row(Status=dps.STATUS_UNREACHABLE, Page_Title="", Page_Description="")
    assert dpl.select_rows_for_llm([garde_echouee, injoignable]) == []


def test_selection_retient_le_texte_fetche_non_classe():
    row = _row()
    assert dpl.select_rows_for_llm([row]) == [row]


# --------------------------------------------------------------------------
# Résolution LLM : ancrage obligatoire, jamais un rapprochement forcé
# --------------------------------------------------------------------------


def test_candidat_ancre_est_accepte(monkeypatch):
    _enable_llm(monkeypatch, lambda *a, **k: _Response(payload=_payload({
        "activity_description": {
            "value": "aide les équipes à mieux vendre",
            "confidence": 0.9,
            "evidence": "Nous aidons les équipes à mieux vendre",
        },
        "activity_sector_match": {
            "value": config.SECTOR_SERVICES,
            "confidence": 0.8,
            "evidence": "Nous aidons les équipes à mieux vendre",
        },
    })))

    report = dpl.enrich_domain_page_sectors(cache_rows=[_row()])

    assert report.calls == 1
    assert report.resolved == 1
    assert report.abstentions == 0
    row = report.cache_rows[0]
    assert row["Status"] == dps.STATUS_MATCHED
    assert row["Activity_Sector_Match"] == config.SECTOR_SERVICES
    assert row["Extraction_Source"] == "llm"


def test_candidat_non_ancre_est_rejete(monkeypatch):
    """Une preuve qui n'est pas une citation exacte du texte fourni est
    rejetée — même garde anti-hallucination que source_facts_ai.py."""
    _enable_llm(monkeypatch, lambda *a, **k: _Response(payload=_payload({
        "activity_description": {
            "value": "vend des voitures",
            "confidence": 0.9,
            "evidence": "phrase totalement inventée absente du texte",
        },
        "activity_sector_match": {
            "value": config.SECTOR_RETAIL,
            "confidence": 0.8,
            "evidence": "phrase totalement inventée absente du texte",
        },
    })))

    report = dpl.enrich_domain_page_sectors(cache_rows=[_row()])

    assert report.calls == 1
    assert report.resolved == 0
    assert report.abstentions == 1
    row = report.cache_rows[0]
    assert row["Status"] == dps.STATUS_NO_EVIDENCE
    assert row["Activity_Sector_Match"] == ""
    assert row["Extraction_Source"] == "llm_declined"


def test_activite_associative_sans_equivalent_reste_inconnue(monkeypatch):
    """Cas réel (audit 2026-08-26, Banque Alimentaire de Strasbourg) : même
    garde que le prompt d'extraction d'article — jamais de rapprochement
    forcé pour une activité associative/caritative."""
    row = _row(Page_Title="", Page_Description="Banque alimentaire de proximité")
    _enable_llm(monkeypatch, lambda *a, **k: _Response(payload=_payload({
        "activity_description": {
            "value": "Banque alimentaire",
            "confidence": 0.9,
            "evidence": "Banque alimentaire de proximité",
        },
        "activity_sector_match": {
            "value": config.SECTOR_UNKNOWN,
            "confidence": 0.9,
            "evidence": "Banque alimentaire de proximité",
        },
    })))

    report = dpl.enrich_domain_page_sectors(cache_rows=[row])

    assert report.resolved == 0
    assert report.cache_rows[0]["Activity_Sector_Match"] == ""


def test_abstention_nest_jamais_redemandee_sans_force(monkeypatch):
    calls = {"n": 0}

    def fake_post(*a, **k):
        calls["n"] += 1
        return _Response(payload=_payload({
            "activity_description": {"value": "x", "confidence": 0.9, "evidence": "Klark"},
            "activity_sector_match": {"value": config.SECTOR_UNKNOWN, "confidence": 0.9, "evidence": "Klark"},
        }))

    _enable_llm(monkeypatch, fake_post)
    declined = dpl.enrich_domain_page_sectors(cache_rows=[_row()]).cache_rows

    report_again = dpl.enrich_domain_page_sectors(cache_rows=declined)
    assert report_again.calls == 0
    assert calls["n"] == 1

    report_forced = dpl.enrich_domain_page_sectors(cache_rows=declined, force=True)
    assert report_forced.calls == 1
    assert calls["n"] == 2


def test_dry_run_never_calls_llm_or_writes(monkeypatch, tmp_path):
    monkeypatch.setattr(dps, "CACHE_CSV", tmp_path / "organisation_domain_page.csv")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(
        llm_runtime.requests, "post",
        lambda *a, **k: pytest.fail("aucun appel LLM ne doit être tenté en dry-run"),
    )

    report = dpl.enrich_domain_page_sectors(cache_rows=[_row()], dry_run=True)

    assert report.calls == 0
    assert not (tmp_path / "organisation_domain_page.csv").exists()


def test_missing_api_key_is_non_blocking():
    report = dpl.enrich_domain_page_sectors(cache_rows=[_row()])
    assert report.llm_available is False
    assert report.calls == 0
    assert report.cache_rows[0]["Status"] == dps.STATUS_NO_EVIDENCE
