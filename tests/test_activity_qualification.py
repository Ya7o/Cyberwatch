"""Qualification sectorielle : décision justifiée, tentatives bornées, alerte.

Les six couples de la collecte `RUN-20260910T125214` sont rejoués depuis leurs
réponses et leurs contextes figés : chaque décision du validateur doit rester
reproductible sans réseau ni clé d'API.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberwatch import qualification, source_facts_ai as sfa, source_facts_retry
from cyberwatch.collectors.base import RawEntry
from cyberwatch.model import Item
from cyberwatch.source_facts_ai_activity import normalize_activity, rejection_kind
from cyberwatch.source_facts_ai_contract import (
    CACHE_STATUS_REJECTED,
    CACHE_STATUS_REJECTED_EXHAUSTED,
    MAX_SEMANTIC_ATTEMPTS,
)

FIXTURE = Path(__file__).parent / "fixtures" / "activity_20260910" / "run_20260910T125214.json"
ACTIVITY_FIELDS = {"activity_description", "activity_sector_match"}

#: Décision attendue pour chacun des six couples réels, motif compris.
EXPECTED = {
    # La citation raconte la cyberattaque : rien n'y décrit le métier.
    "ITM-0c085da888611a12": ("ACTIVITY_NOT_DESCRIBED", "ACTIVITY_NOT_DESCRIBED"),
    # Appartenance à un groupe puis incident : aucune activité prédiquée.
    "ITM-3a1f12b53d6e809e": ("ACTIVITY_NOT_DESCRIBED", "ACTIVITY_NOT_DESCRIBED"),
    # « chez l'un de ses prestataires chargé du suivi des commandes » : Shipup.
    "ITM-56fe2e286f88ef44": ("ACTIVITY_THIRD_PARTY", "THIRD_PARTY_ACTIVITY"),
    # « La mairie » sans rattachement, et une seconde collectivité dans la fenêtre.
    "ITM-f2c9b54af4eae1da": ("ACTIVITY_IDENTITY_AMBIGUOUS", "AMBIGUOUS_IDENTITY"),
    # Citation tronquée par une ellipse ajoutée, valeur venue d'ailleurs.
    "ITM-5d429a6cb36dada4": ("EVIDENCE_NOT_GROUNDED", "EVIDENCE_NOT_FOUND"),
    # Fragment de phrase décrivant le flux de données de l'incident.
    "ITM-297a7e21d0f7da49": ("ACTIVITY_NOT_DESCRIBED", "ACTIVITY_NOT_DESCRIBED"),
}


def _cases():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]


def _item(source="CYBERATTAQUE_ORG", organisation="Exemple SA"):
    return Item(Item_ID="ITM-activity", Source_ID=source, Organisation_Raw=organisation,
                Published_Date="2026-09-10")


def _configure(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    monkeypatch.setenv("SOURCE_FACTS_AI_STATS_PATH", str(tmp_path / "stats.json"))
    monkeypatch.setenv("SOURCE_FACTS_RETRY_QUEUE_PATH", str(tmp_path / "retry.json"))
    sfa.reset_runtime_for_tests()


# --- 1. Les six couples réels ------------------------------------------------

@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["item_id"])
def test_chaque_couple_reel_recoit_une_decision_justifiee(case):
    """Aucun couple ne repart avec un motif fourre-tout."""
    result, reasons = normalize_activity(case["proposal"], case["context"], case["organisation"])
    expected_reason, expected_kind = EXPECTED[case["item_id"]]
    assert "activity_description" not in result
    assert reasons["activity_description"] == expected_reason
    assert rejection_kind(reasons["activity_description"]) == expected_kind


def test_le_run_de_reference_n_accepte_aucun_couple():
    """0/6 accepté : le bilan réel de la collecte, motifs tous circonstanciés."""
    accepted = 0
    kinds = set()
    for case in _cases():
        result, reasons = normalize_activity(
            case["proposal"], case["context"], case["organisation"]
        )
        accepted += int(ACTIVITY_FIELDS <= set(result))
        kinds.add(rejection_kind(reasons["activity_description"]))
    assert accepted == 0
    assert kinds == {"ACTIVITY_NOT_DESCRIBED", "THIRD_PARTY_ACTIVITY",
                     "AMBIGUOUS_IDENTITY", "EVIDENCE_NOT_FOUND"}


def test_le_secteur_de_reference_survit_a_un_rejet_de_tiers():
    """Printemps : `Transport / Logistique` refusé, rien n'est publié à la place."""
    case = next(c for c in _cases() if c["item_id"] == "ITM-56fe2e286f88ef44")
    assert case["proposal"]["activity_sector_match"]["value"] == "Transport / Logistique"
    result, reasons = normalize_activity(case["proposal"], case["context"], case["organisation"])
    assert result == {}
    assert reasons["activity_sector_match"] == "NO_VALID_ACTIVITY_PAIR"


# --- 2. « la mairie » : rattachement explicite contre ambiguïté ---------------

@pytest.mark.parametrize("context,accepte", [
    ("Les services sont perturbés. La mairie du Tampon gère de nombreux services publics.", True),
    ("Le Tampon a publié un communiqué. La mairie gère de nombreux services publics.", True),
    ("Le Tampon et Saint-Pierre coopèrent. La mairie de Saint-Pierre gère des services publics.", False),
    ("Le Tampon appartient à la Communauté d'agglomération du Sud. "
     "La mairie gère de nombreux services publics.", False),
    ("Une cyberattaque a eu lieu. La mairie gère de nombreux services publics.", False),
])
def test_la_mairie_exige_un_rattachement_explicite_et_non_ambigu(context, accepte):
    evidence = context.split(". ", 1)[1]
    raw = {
        "activity_description": {"value": "Gestion de services publics.",
                                 "confidence": 0.9, "evidence": evidence},
        "activity_sector_match": {"value": "Administration / Collectivité",
                                  "confidence": 0.9, "evidence": evidence},
    }
    result, reasons = normalize_activity(raw, context, "Le Tampon")
    if accepte:
        assert result["activity_sector_match"]["value"] == "Administration / Collectivité"
    else:
        assert result == {}
        assert rejection_kind(reasons["activity_description"]) == "AMBIGUOUS_IDENTITY"


def test_une_citation_inventee_est_rejetee_malgre_une_confiance_de_090():
    contexte = "Printemps informe ses clients d'un incident chez un prestataire."
    raw = {
        "activity_description": {"value": "Printemps est une enseigne de vente au détail.",
                                 "confidence": 0.9,
                                 "evidence": "Printemps informe certains de ses clients que…"},
        "activity_sector_match": {"value": "Commerce / Distribution", "confidence": 0.9,
                                  "evidence": "Printemps informe certains de ses clients que…"},
    }
    result, reasons = normalize_activity(raw, contexte, "Printemps")
    assert result == {}
    assert reasons["activity_description"] == "EVIDENCE_NOT_GROUNDED"


# --- 3. Abstention, tentatives et rejet persistant ----------------------------

def _reject_once(runtime, target, previous=None):
    raw = {"activity_description": {"value": "suivi des commandes", "confidence": 0.9,
                                    "evidence": "chez l un de ses prestataires"}}
    sfa._store_field_cache(runtime, "k", None, None, {"activity_description"}, {},
                           raw=raw, reasons={"activity_description": "ACTIVITY_THIRD_PARTY"})
    return target["activity_description"]


def test_une_absence_d_activite_est_terminale_sans_boucle_de_reprise(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    runtime = sfa._runtime()
    runtime.cache["k"] = {"fields": {}}
    sfa._store_field_cache(runtime, "k", None, None, ACTIVITY_FIELDS, {},
                           raw={}, reasons={})
    for field in ACTIVITY_FIELDS:
        assert runtime.cache["k"]["fields"][field]["status"] == "abstained"
    _, satisfied = sfa._read_field_cache(runtime, "k", set(ACTIVITY_FIELDS))
    assert satisfied == ACTIVITY_FIELDS  # aucun appel ne repartira


def test_deux_rejets_epuisent_les_tentatives_puis_coupent_les_appels(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    runtime = sfa._runtime()
    runtime.cache["k"] = {"fields": {}}
    target = runtime.cache["k"]["fields"]

    record = _reject_once(runtime, target)
    assert (record["status"], record["semantic_attempts"]) == (CACHE_STATUS_REJECTED, 1)
    _, satisfied = sfa._read_field_cache(runtime, "k", {"activity_description"})
    assert satisfied == set()  # rejouable : le champ est redemandé

    record = _reject_once(runtime, target)
    assert record["semantic_attempts"] == MAX_SEMANTIC_ATTEMPTS
    assert record["status"] == CACHE_STATUS_REJECTED_EXHAUSTED
    _, satisfied = sfa._read_field_cache(runtime, "k", {"activity_description"})
    assert satisfied == {"activity_description"}  # plus aucun appel automatique
    assert runtime.rejected_field_cache_hits == 1


def test_un_changement_de_version_rouvre_deux_tentatives_sans_purge(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    runtime = sfa._runtime()
    runtime.cache["k"] = {"fields": {}}
    target = runtime.cache["k"]["fields"]
    _reject_once(runtime, target)
    _reject_once(runtime, target)
    assert target["activity_description"]["status"] == CACHE_STATUS_REJECTED_EXHAUSTED

    monkeypatch.setitem(sfa.FIELD_VERSIONS, "activity_description", "activity-description-v99")
    assert sfa._semantic_attempts(target["activity_description"], "activity_description") == 0
    # L'enregistrement n'a pas été effacé : sa raison reste lisible.
    assert target["activity_description"]["rejection_reason"] == "ACTIVITY_THIRD_PARTY"


def test_une_panne_technique_ne_consomme_aucune_tentative(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    runtime = sfa._runtime()

    def _boom(*_args, **_kwargs):
        raise sfa.SourceFactsAiError("timeout")

    monkeypatch.setattr(sfa, "_post_openai", _boom)
    entry = RawEntry(title="Exemple SA", content="Exemple SA a subi un incident.")
    normalized, succeeded = sfa._perform_request(
        _item(), entry, "Exemple SA a subi un incident.",
        set(ACTIVITY_FIELDS), runtime, "k",
    )
    assert (normalized, succeeded) == ({}, False)
    assert runtime.cache.get("k") is None
    assert runtime.pair_counts()["technical_failure"]["total"] == 1


# --- 4. Compteurs, verdict et alerte ----------------------------------------

def test_les_couples_sont_comptes_une_fois_selon_leur_dernier_resultat(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    runtime = sfa._runtime()
    runtime.record_pair_outcome("ITM-1", "h1", "rejected", origin="cache")
    runtime.record_pair_outcome("ITM-1", "h1", "accepted", origin="call")
    runtime.record_pair_outcome("ITM-2", "h2", "abstained", origin="call")
    counts = runtime.pair_counts()
    assert counts["requested"] == 2
    assert counts["accepted"] == {"total": 1, "from_cache": 0, "from_call": 1}
    assert "rejected" not in counts  # écrasé par le dernier résultat du run


@pytest.mark.parametrize("outcome,attendu_partial", [
    ("accepted", False),
    ("abstained", False),          # une abstention explicite n'est pas un échec
    ("rejected", True),
    ("rejected_exhausted", True),  # l'alerte reste active après épuisement
    ("technical_failure", True),
])
def test_le_verdict_devient_partiel_sur_un_couple_non_resolu(outcome, attendu_partial):
    """Une réponse API réussie qui laisse un rejet à traiter produit PARTIAL."""
    run = qualification.QualificationRun(
        run_id="RUN-TEST",
        extraction={"items_would_call": 1, "calls_attempted": 1,
                    "activity_pairs": {"requested": 1,
                                       outcome: {"total": 1, "from_cache": 0, "from_call": 1}}},
        documented=True,
    )
    verdict = qualification.evaluate(run)
    assert (verdict["state"] == qualification.STATE_PARTIAL) is attendu_partial


def _deferred(reason, fields, item_id="ITM-test"):
    return {"item": {"Item_ID": item_id}, "pending_fields": list(fields), "reason": reason}


def test_une_absence_dans_la_source_ne_declenche_pas_d_alerte():
    """Un champ que l'article ne documente pas est un fait éditorial.

    Le run reste PARTIAL à cause de la panne, mais le motif ne cite que les
    champs réellement dus : les deux familles de motifs ne se confondent pas.
    """
    run = qualification.QualificationRun(
        run_id="RUN-TEST", documented=True, deferred_source="archive",
        extraction={"items_would_call": 2, "calls_attempted": 2},
        deferred=[
            _deferred("SEMANTIC_MISS", ["attack_date", "impact"], "ITM-absent"),
            _deferred("TECHNICAL_FAILURE", ["summary"], "ITM-panne"),
        ],
    )
    verdict = qualification.evaluate(run)
    assert verdict["state"] == qualification.STATE_PARTIAL
    assert verdict["pending_fields"] == 3          # la télémétrie garde tout
    assert verdict["pending_required_fields"] == 1  # seule la panne est due
    assert any("1 champ(s) d'extraction différé(s)" in reason
               for reason in verdict["reasons"])


def test_un_run_sans_panne_reste_complet_malgre_des_champs_non_documentes():
    run = qualification.QualificationRun(
        run_id="RUN-TEST", documented=True, deferred_source="archive",
        extraction={"items_would_call": 1, "calls_attempted": 1},
        deferred=[_deferred("SEMANTIC_MISS", ["attack_date", "vulnerabilities"])],
    )
    verdict = qualification.evaluate(run)
    assert verdict["state"] == qualification.STATE_COMPLETE
    assert verdict["pending_fields"] == 2
    assert verdict["pending_required_fields"] == 0


def test_un_motif_de_report_inconnu_continue_d_alerter():
    """Le vocabulaire des motifs est ouvert : le silence ne relâche rien."""
    run = qualification.QualificationRun(
        run_id="RUN-TEST", documented=True, deferred_source="archive",
        extraction={"items_would_call": 1, "calls_attempted": 1},
        deferred=[_deferred("", ["summary"]), _deferred("COST_LIMIT", ["impact"])],
    )
    verdict = qualification.evaluate(run)
    assert verdict["state"] == qualification.STATE_PARTIAL
    assert verdict["pending_required_fields"] == 2


def test_l_alerte_de_production_reprend_le_motif_de_rejet(monkeypatch):
    from cyberwatch import production

    monkeypatch.setattr(production.qualification, "payload", lambda _run_id: {
        "run_id": "RUN-TEST", "state": qualification.STATE_PARTIAL,
        "reasons": ["1 couple(s) activité/secteur en rejet persistant (tentatives épuisées)"],
        "pending_fields": 0, "pending_fields_available": True,
        "pending_pairs": 0, "pairs": None, "label": qualification.INCOMPLETE_LABEL,
    })
    payload = production.health_payload()
    assert payload["alert"] is True
    assert any("rejet persistant" in reason for reason in payload["alert_reasons"])


# --- 5. Rapport, archive et reprise ciblée ----------------------------------

def test_le_rapport_affiche_la_valeur_rejetee_et_sa_preuve():
    case = next(c for c in _cases() if c["item_id"] == "ITM-56fe2e286f88ef44")
    proposal = case["proposal"]["activity_description"]
    run = qualification.QualificationRun(
        run_id="RUN-TEST",
        trace=[{"item_id": case["item_id"], "status": "success",
                "requested_fields": ["activity_description"],
                "normalized": {},
                "proposals": {"activity_description": proposal},
                "rejections": {"activity_description": "ACTIVITY_THIRD_PARTY"},
                "rejection_kinds": {"activity_description": "THIRD_PARTY_ACTIVITY"}}],
        documented=True,
    )
    row = qualification.extraction_rows(run)[0]
    assert row["value"] == proposal["value"]
    assert row["evidence"] == proposal["evidence"]
    assert row["validation"] == "rejected"
    assert row["rejection"] == "ACTIVITY_THIRD_PARTY (THIRD_PARTY_ACTIVITY)"
    assert row["kept"] == ""


def test_un_rapport_historique_ne_depend_plus_de_la_file_courante(monkeypatch, tmp_path):
    """L'archive de fin de run fait autorité ; la file vivante ne la corrige pas."""
    monkeypatch.setenv("SOURCE_FACTS_RETRY_QUEUE_PATH", str(tmp_path / "retry.json"))
    runs = tmp_path / "llm_runs" / "RUN-ANCIEN"
    runs.mkdir(parents=True)
    (runs / "source_facts_ai_usage.json").write_text('{"items_would_call": 1}', encoding="utf-8")
    (runs / "source_facts_retry_queue.json").write_text(
        json.dumps({"version": 2, "run_id": "RUN-ANCIEN",
                    "entries": [{"key": "k", "pending_fields": ["activity_description"]}]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(source_facts_retry, "load", lambda: [
        {"key": "autre", "pending_fields": ["summary", "impact", "attack_flow"]},
    ])
    verdict = qualification.evaluate(qualification.load_run("RUN-ANCIEN", tmp_path))
    assert verdict["pending_fields"] == 1
    assert verdict["pending_fields_available"] is True


def test_un_run_sans_archive_ni_trace_dit_non_disponible(monkeypatch, tmp_path):
    monkeypatch.setenv("SOURCE_FACTS_RETRY_QUEUE_PATH", str(tmp_path / "retry.json"))
    for name in ("RUN-ANCIEN", "RUN-RECENT"):
        directory = tmp_path / "llm_runs" / name
        directory.mkdir(parents=True)
        (directory / "source_facts_ai_usage.json").write_text("{}", encoding="utf-8")
    verdict = qualification.evaluate(qualification.load_run("RUN-ANCIEN", tmp_path))
    assert verdict["pending_fields_available"] is False
    assert "_non disponible_" in qualification.markdown_report(
        qualification.load_run("RUN-ANCIEN", tmp_path)
    )


def test_un_rejet_persistant_reste_visible_sans_etre_rejouable(monkeypatch, tmp_path):
    monkeypatch.setenv("SOURCE_FACTS_RETRY_QUEUE_PATH", str(tmp_path / "retry.json"))
    item, entry = _item(), RawEntry(title="Exemple SA", content="Incident")
    source_facts_retry.enqueue(item, entry, set(ACTIVITY_FIELDS), "SEMANTIC_REJECTED")
    source_facts_retry.mark_exhausted(item, entry, set(ACTIVITY_FIELDS),
                                      {"activity_description": "ACTIVITY_THIRD_PARTY"})
    rows = source_facts_retry.load()
    assert len(rows) == 1  # le dossier n'a pas disparu
    assert rows[0]["pending_fields"] == []
    assert set(rows[0]["exhausted_fields"]) == ACTIVITY_FIELDS
    assert source_facts_retry.pending_for(rows[0]) == set()


def test_une_reprise_sectorielle_ne_touche_pas_les_autres_champs(monkeypatch, tmp_path):
    monkeypatch.setenv("SOURCE_FACTS_RETRY_QUEUE_PATH", str(tmp_path / "retry.json"))
    item, entry = _item(), RawEntry(title="Exemple SA", content="Incident")
    source_facts_retry.enqueue(
        item, entry, ACTIVITY_FIELDS | {"summary", "impact"}, "SEMANTIC_MISS"
    )
    row = source_facts_retry.load()[0]
    assert source_facts_retry.pending_for(row, ACTIVITY_FIELDS) == ACTIVITY_FIELDS

    source_facts_retry.resolve(item, entry, set(ACTIVITY_FIELDS))
    # Les champs hors périmètre restent en attente, sans avoir été recalculés.
    assert source_facts_retry.load()[0]["pending_fields"] == ["impact", "summary"]


def test_une_file_ancienne_reste_lisible(monkeypatch, tmp_path):
    """Aucune purge, aucune réécriture : la version 1 se relit telle quelle."""
    path = tmp_path / "retry.json"
    monkeypatch.setenv("SOURCE_FACTS_RETRY_QUEUE_PATH", str(path))
    path.write_text(json.dumps({"version": 1, "entries": [
        {"key": "ancien", "pending_fields": ["activity_description"], "reason": "SEMANTIC_MISS",
         "item": {}, "entry": {}, "attempts": 0},
    ]}), encoding="utf-8")
    rows = source_facts_retry.load()
    assert rows[0]["key"] == "ancien"
    assert rows[0].get("exhausted_fields") is None
    assert source_facts_retry.pending_for(rows[0]) == {"activity_description"}


def test_l_archive_suit_le_chemin_de_la_file(monkeypatch, tmp_path):
    """Une redirection de test n'écrit jamais dans le `data/` du dépôt."""
    monkeypatch.setenv("SOURCE_FACTS_RETRY_QUEUE_PATH", str(tmp_path / "retry.json"))
    item, entry = _item(), RawEntry(title="Exemple SA", content="Incident")
    source_facts_retry.enqueue(item, entry, set(ACTIVITY_FIELDS), "SEMANTIC_REJECTED")

    path = source_facts_retry.archive("RUN-ARCHIVE-TEST")
    assert path == tmp_path / "llm_runs" / "RUN-ARCHIVE-TEST" / "source_facts_retry_queue.json"
    archived = json.loads(path.read_text(encoding="utf-8"))
    assert archived["run_id"] == "RUN-ARCHIVE-TEST"
    assert archived["entries"][0]["pending_fields"] == sorted(ACTIVITY_FIELDS)

    # La file continue de vivre : l'archive en est une copie, pas un transfert.
    assert len(source_facts_retry.load()) == 1


def test_une_relecture_de_cache_ne_compte_pas_un_rejet_comme_une_abstention():
    """La trace d'un `cache_read` porte les statuts : les lire, pas les deviner."""
    run = qualification.QualificationRun(
        run_id="RUN-TEST",
        trace=[{"item_id": "ITM-1", "content_hash": "h1", "status": "cache_read",
                "requested_fields": sorted(ACTIVITY_FIELDS),
                "fields": {field: {"status": CACHE_STATUS_REJECTED_EXHAUSTED,
                                   "rejection_reason": "ACTIVITY_THIRD_PARTY"}
                           for field in ACTIVITY_FIELDS}}],
        documented=True,
    )
    counts = qualification.evaluate(run)["extraction"]["pairs"]
    assert counts["rejected_exhausted"] == {"total": 1, "from_cache": 1, "from_call": 0}
    assert "abstained" not in counts


def test_un_audit_sans_file_figee_ne_pretend_pas_zero():
    run = qualification.run_from_snapshot({"run": [{"Run_ID": "RUN-AUDIT"}]})
    assert qualification.evaluate(run)["pending_fields_available"] is False

    run = qualification.run_from_snapshot({
        "run": [{"Run_ID": "RUN-AUDIT"}],
        "extraction_usage": {"items_would_call": 1},
        "deferred_entries": {"version": 1, "entries": [
            {"key": "k", "pending_fields": ["activity_description", "summary"]},
        ]},
    })
    verdict = qualification.evaluate(run)
    assert (verdict["pending_fields"], verdict["pending_fields_available"]) == (2, True)
