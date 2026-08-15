"""Filet de rattrapage LLM : politique d'écrasement, cache, budget, panne."""

from __future__ import annotations

import json

import pytest

from cyberwatch import ai, config, runner, store
from cyberwatch.collectors.base import RawEntry, SourceSpec

SPEC = SourceSpec(
    source_id="FRENCHBREACHES",
    layer=config.LAYER_CORE,
    zone=config.LOC_FRANCE,
    collector="feed",
    active=True,
)

ENTRY = RawEntry(
    title="La mairie de Testville victime d'un rançongiciel",
    summary="Les données des habitants ont été chiffrées puis une rançon exigée.",
    content="Le groupe LockBit revendique l'attaque. Aucune rançon n'a été payée.",
    published="2026-06-01",
    organisation="Mairie de Testville",
)


@pytest.fixture(autouse=True)
def _isolate_ai_csvs(tmp_path, monkeypatch):
    """`ai.finish_run` persiste le cache : jamais vers les vrais fichiers du dépôt."""
    monkeypatch.setattr(store, "AI_QUALIFICATIONS_CSV", tmp_path / "ai_qualifications.csv")
    monkeypatch.setattr(store, "AI_USAGE_CSV", tmp_path / "ai_usage.csv")


def _field(value: str, confidence: float = 0.9, evidence: str = "preuve") -> dict:
    return {"value": value, "confidence": confidence, "evidence": evidence}


def _payload(usage: dict | None = None, **fields) -> dict:
    text = json.dumps(fields)
    return {
        "output": [{"type": "message", "content": [{"type": "output_text", "text": text}]}],
        "usage": usage or {"input_tokens": 100, "output_tokens": 20, "total_tokens": 120},
    }


def enabled_state(**overrides) -> ai.AiRunState:
    defaults = dict(enabled=True, api_key="test-key", model=ai.DEFAULT_MODEL)
    defaults.update(overrides)
    return ai.AiRunState(**defaults)


# --------------------------------------------------------------------------
# Politique d'écrasement
# --------------------------------------------------------------------------


class TestOverwritePolicy:
    def test_item_entierement_connu_ne_declenche_aucun_appel(self, make_item, monkeypatch):
        item = make_item(threat="Ransomware", sector="Santé", location="La Réunion")
        state = enabled_state()
        monkeypatch.setattr(ai, "_call_openai", lambda *a, **k: pytest.fail("appel inattendu"))

        ai.qualify_item(item, ENTRY, SPEC, state)

        assert state.candidates == 0
        assert state.calls_attempted == 0

    def test_seul_le_champ_inconnu_demande_change(self, make_item, monkeypatch):
        item = make_item(threat=config.THREAT_UNKNOWN, sector="Santé", location="La Réunion")
        monkeypatch.setattr(
            ai, "_call_openai",
            lambda *a, **k: _payload(threat=_field("Ransomware")),
        )
        state = enabled_state()

        ai.qualify_item(item, ENTRY, SPEC, state)

        assert item.Threat == "Ransomware"
        assert item.Sector == "Santé"
        assert item.Location == "La Réunion"

    def test_valeur_connue_jamais_ecrasee_meme_si_le_llm_repond_autre_chose(self, make_item, monkeypatch):
        item = make_item(threat=config.THREAT_UNKNOWN, sector="Santé", location="La Réunion")
        # Le schéma n'aurait normalement demandé que "threat", mais un
        # fournisseur de test malveillant/buggé pourrait renvoyer plus :
        # seuls les champs *demandés* et encore Inconnu doivent être appliqués.
        monkeypatch.setattr(
            ai, "_call_openai",
            lambda *a, **k: _payload(
                threat=_field("Ransomware"),
                sector=_field("Énergie / Utilities"),
            ),
        )
        state = enabled_state()

        ai.qualify_item(item, ENTRY, SPEC, state)

        assert item.Threat == "Ransomware"
        assert item.Sector == "Santé"  # inchangé : ce n'était pas demandé

    def test_valeur_hors_enum_rejetee(self, make_item, monkeypatch):
        item = make_item(threat=config.THREAT_UNKNOWN)
        monkeypatch.setattr(
            ai, "_call_openai",
            lambda *a, **k: _payload(threat=_field("Cyberattaque générique")),
        )
        state = enabled_state()

        ai.qualify_item(item, ENTRY, SPEC, state)

        assert item.Threat == config.THREAT_UNKNOWN
        assert state.calls_failed == 1

    def test_json_invalide_conserve_inconnu(self, make_item, monkeypatch):
        item = make_item(threat=config.THREAT_UNKNOWN)
        payload = {"output": [{"type": "message", "content": [{"type": "output_text", "text": "{not json"}]}]}
        monkeypatch.setattr(ai, "_call_openai", lambda *a, **k: payload)
        state = enabled_state()

        ai.qualify_item(item, ENTRY, SPEC, state)

        assert item.Threat == config.THREAT_UNKNOWN
        assert state.calls_failed == 1
        assert state.calls_succeeded == 0

    def test_confidence_insuffisante_garde_inconnu(self, make_item, monkeypatch):
        item = make_item(sector=config.SECTOR_UNKNOWN)
        monkeypatch.setattr(
            ai, "_call_openai",
            lambda *a, **k: _payload(sector=_field("Santé", confidence=0.2)),
        )
        state = enabled_state()

        ai.qualify_item(item, ENTRY, SPEC, state)

        assert item.Sector == config.SECTOR_UNKNOWN
        # La réponse était structurée et valide : c'est un succès d'appel,
        # simplement en dessous du seuil d'application.
        assert state.calls_succeeded == 1

    def test_location_sans_evidence_dans_le_contexte_reste_inconnue(self, make_item, monkeypatch):
        item = make_item(location=config.LOC_INCONNU)
        monkeypatch.setattr(
            ai, "_call_openai",
            lambda *a, **k: _payload(location=_field("Maurice", evidence="île sœur")),
        )
        state = enabled_state()

        ai.qualify_item(item, ENTRY, SPEC, state)

        # "île sœur" n'apparaît pas dans le contexte transmis : réponse rejetée.
        assert item.Location == config.LOC_INCONNU
        assert state.calls_failed == 1

    def test_location_avec_evidence_presente_dans_le_contexte_est_appliquee(self, make_item, monkeypatch):
        item = make_item(location=config.LOC_INCONNU)
        entry = RawEntry(title="Incident", summary="L'attaque visait une mairie de La Réunion.", published="2026-06-01")
        monkeypatch.setattr(
            ai, "_call_openai",
            lambda *a, **k: _payload(location=_field("La Réunion", evidence="mairie de La Réunion")),
        )
        state = enabled_state()

        ai.qualify_item(item, entry, SPEC, state)

        assert item.Location == "La Réunion"


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------


class TestCache:
    def test_cache_hit_zero_appel(self, make_item, monkeypatch):
        item = make_item(threat=config.THREAT_UNKNOWN)
        input_hash = ai._input_hash(item, ENTRY, ["Threat"], ai.DEFAULT_MODEL, 4000)
        state = enabled_state()
        state.cache[(item.Item_ID, input_hash)] = {
            "Threat": "Ransomware", "Threat_Confidence": "0.9", "Threat_Evidence": "preuve",
        }
        monkeypatch.setattr(ai, "_call_openai", lambda *a, **k: pytest.fail("appel inattendu"))

        ai.qualify_item(item, ENTRY, SPEC, state)

        assert item.Threat == "Ransomware"
        assert state.cache_hits == 1
        assert state.calls_attempted == 0

    def test_meme_input_hash_donne_meme_decision(self, make_item, monkeypatch):
        item_a = make_item(threat=config.THREAT_UNKNOWN, source_item_id="a")
        item_b = make_item(threat=config.THREAT_UNKNOWN, source_item_id="a")
        calls = []
        monkeypatch.setattr(
            ai, "_call_openai",
            lambda *a, **k: calls.append(1) or _payload(threat=_field("Ransomware")),
        )
        state = enabled_state()

        ai.qualify_item(item_a, ENTRY, SPEC, state)
        ai.qualify_item(item_b, ENTRY, SPEC, state)

        assert item_a.Threat == item_b.Threat == "Ransomware"

    def test_changement_de_contexte_donne_un_nouveau_input_hash(self, make_item):
        item = make_item(threat=config.THREAT_UNKNOWN)
        other_entry = RawEntry(title="Autre titre", summary="Autre résumé", published="2026-06-01")

        h1 = ai._input_hash(item, ENTRY, ["Threat"], ai.DEFAULT_MODEL, 4000)
        h2 = ai._input_hash(item, other_entry, ["Threat"], ai.DEFAULT_MODEL, 4000)

        assert h1 != h2

    def test_changement_de_prompt_version_donne_un_nouveau_input_hash(self, make_item, monkeypatch):
        item = make_item(threat=config.THREAT_UNKNOWN)
        h1 = ai._input_hash(item, ENTRY, ["Threat"], ai.DEFAULT_MODEL, 4000)
        monkeypatch.setattr(ai, "PROMPT_VERSION", "autre-version")
        h2 = ai._input_hash(item, ENTRY, ["Threat"], ai.DEFAULT_MODEL, 4000)

        assert h1 != h2

    def test_ordre_des_items_sans_effet_sur_le_cache_final(self, make_item, monkeypatch):
        monkeypatch.setattr(
            ai, "_call_openai",
            lambda *a, **k: _payload(threat=_field("Ransomware")),
        )

        # Chaque état reçoit ses propres instances : `qualify_item` mute
        # l'item en place, donc réutiliser les mêmes objets entre les deux
        # passes fausserait le test (le second passage les verrait déjà
        # qualifiés par le premier).
        state1 = enabled_state()
        ai.qualify_item(make_item(threat=config.THREAT_UNKNOWN, source_item_id="a"), ENTRY, SPEC, state1)
        ai.qualify_item(make_item(threat=config.THREAT_UNKNOWN, source_item_id="b"), ENTRY, SPEC, state1)

        state2 = enabled_state()
        ai.qualify_item(make_item(threat=config.THREAT_UNKNOWN, source_item_id="b"), ENTRY, SPEC, state2)
        ai.qualify_item(make_item(threat=config.THREAT_UNKNOWN, source_item_id="a"), ENTRY, SPEC, state2)

        assert set(state1.cache.keys()) == set(state2.cache.keys())


# --------------------------------------------------------------------------
# Robustesse réseau
# --------------------------------------------------------------------------


class TestNetworkRobustness:
    def test_429_puis_succes_est_retente(self, make_item, monkeypatch):
        item = make_item(threat=config.THREAT_UNKNOWN)
        responses = iter([
            _FakeResponse(429, ""),
            _FakeResponse(200, json.dumps(_payload(threat=_field("Ransomware")))),
        ])
        monkeypatch.setattr(ai.requests, "post", lambda *a, **k: next(responses))
        monkeypatch.setattr(ai.time, "sleep", lambda *_: None)
        state = enabled_state()

        ai.qualify_item(item, ENTRY, SPEC, state)

        assert item.Threat == "Ransomware"
        assert state.calls_succeeded == 1

    def test_timeout_est_retente_puis_echoue_proprement(self, make_item, monkeypatch):
        item = make_item(threat=config.THREAT_UNKNOWN)

        def always_timeout(*a, **k):
            raise ai.requests.Timeout("délai dépassé")

        monkeypatch.setattr(ai.requests, "post", always_timeout)
        monkeypatch.setattr(ai.time, "sleep", lambda *_: None)
        state = enabled_state()

        ai.qualify_item(item, ENTRY, SPEC, state)

        assert item.Threat == config.THREAT_UNKNOWN
        assert state.calls_failed == 1

    def test_panne_definitive_le_run_continue_sans_rien_inventer(self, make_item, monkeypatch):
        item = make_item(threat=config.THREAT_UNKNOWN, sector=config.SECTOR_UNKNOWN)
        monkeypatch.setattr(ai.requests, "post", lambda *a, **k: _FakeResponse(500, ""))
        monkeypatch.setattr(ai.time, "sleep", lambda *_: None)
        state = enabled_state()

        ai.qualify_item(item, ENTRY, SPEC, state)
        row = ai.finish_run(state, "RUN-TEST", "2026-08-15T00:00:00+04:00", "MAJ")

        assert item.Threat == config.THREAT_UNKNOWN
        assert item.Sector == config.SECTOR_UNKNOWN
        assert row["Status"] == "API_ERROR"


class _FakeResponse:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text

    def json(self):
        return json.loads(self.text)


# --------------------------------------------------------------------------
# Budget
# --------------------------------------------------------------------------


class TestBudget:
    def test_plafond_appels_atteint_bloque_les_suivants(self, make_item, monkeypatch):
        calls = []
        monkeypatch.setattr(
            ai, "_call_openai",
            lambda *a, **k: calls.append(1) or _payload(threat=_field("Ransomware")),
        )
        state = enabled_state(max_calls=1)
        item_a = make_item(threat=config.THREAT_UNKNOWN, source_item_id="a")
        item_b = make_item(threat=config.THREAT_UNKNOWN, source_item_id="b")

        ai.qualify_item(item_a, ENTRY, SPEC, state)
        ai.qualify_item(item_b, ENTRY, SPEC, state)

        assert len(calls) == 1
        assert item_b.Threat == config.THREAT_UNKNOWN
        assert state.calls_budget_blocked == 1
        assert state.budget_stopped is True

    def test_plafond_cout_atteint_bloque_les_suivants(self, make_item, monkeypatch):
        monkeypatch.setattr(
            ai, "_call_openai",
            lambda *a, **k: _payload(
                threat=_field("Ransomware"),
                usage={"input_tokens": 1_000_000, "output_tokens": 0, "total_tokens": 1_000_000},
            ),
        )
        state = enabled_state(max_cost=0.01)  # 1e6 tokens d'entrée coûte déjà 0.05$
        item_a = make_item(threat=config.THREAT_UNKNOWN, source_item_id="a")
        item_b = make_item(threat=config.THREAT_UNKNOWN, source_item_id="b")

        ai.qualify_item(item_a, ENTRY, SPEC, state)
        ai.qualify_item(item_b, ENTRY, SPEC, state)

        assert item_a.Threat == "Ransomware"
        assert item_b.Threat == config.THREAT_UNKNOWN
        assert state.calls_budget_blocked == 1


# --------------------------------------------------------------------------
# Comptabilité
# --------------------------------------------------------------------------


class TestAccounting:
    def test_calcul_de_cout_exact_sur_fixture_connue(self):
        cost = ai._estimate_cost(ai.DEFAULT_MODEL, input_tokens=1_000_000, output_tokens=1_000_000)
        assert cost == pytest.approx(0.05 + 0.40)

    def test_compteurs_ai_usage_exacts(self, make_item, monkeypatch):
        monkeypatch.setattr(
            ai, "_call_openai",
            lambda *a, **k: _payload(threat=_field("Ransomware")),
        )
        state = enabled_state()
        item = make_item(threat=config.THREAT_UNKNOWN, sector="Santé", location="La Réunion")

        ai.qualify_item(item, ENTRY, SPEC, state)
        row = ai.finish_run(state, "RUN-TEST", "2026-08-15T00:00:00+04:00", "MAJ")

        assert row["Candidates"] == 1
        assert row["Calls_Attempted"] == 1
        assert row["Calls_Succeeded"] == 1
        assert row["Threat_Unknown_Before"] == 1
        assert row["Threat_Qualified"] == 1
        assert row["Sector_Unknown_Before"] == 0
        assert row["Still_Unknown"] == 0
        assert row["Status"] == "OK"

    def test_tokens_additionnes_correctement(self, make_item, monkeypatch):
        monkeypatch.setattr(
            ai, "_call_openai",
            lambda *a, **k: _payload(
                threat=_field("Ransomware"),
                usage={"input_tokens": 111, "output_tokens": 22, "total_tokens": 133},
            ),
        )
        state = enabled_state()
        item_a = make_item(threat=config.THREAT_UNKNOWN, source_item_id="a")
        item_b = make_item(threat=config.THREAT_UNKNOWN, source_item_id="b")

        ai.qualify_item(item_a, ENTRY, SPEC, state)
        ai.qualify_item(item_b, ENTRY, SPEC, state)

        assert state.input_tokens == 222
        assert state.output_tokens == 44
        assert state.total_tokens == 266


# --------------------------------------------------------------------------
# Intégrité (Item_ID / Organisation_Key / REPLAY / test-repeat)
# --------------------------------------------------------------------------


class TestIdentitySafety:
    def test_item_id_jamais_modifie(self, make_item, monkeypatch):
        item = make_item(threat=config.THREAT_UNKNOWN)
        before = item.Item_ID
        monkeypatch.setattr(
            ai, "_call_openai",
            lambda *a, **k: _payload(threat=_field("Ransomware")),
        )
        ai.qualify_item(item, ENTRY, SPEC, enabled_state())

        assert item.Item_ID == before

    def test_organisation_key_jamais_modifie(self, make_item, monkeypatch):
        item = make_item(threat=config.THREAT_UNKNOWN)
        before = item.Organisation_Key
        monkeypatch.setattr(
            ai, "_call_openai",
            lambda *a, **k: _payload(threat=_field("Ransomware")),
        )
        ai.qualify_item(item, ENTRY, SPEC, enabled_state())

        assert item.Organisation_Key == before

    def test_replay_zero_appel_openai(self, tmp_path, monkeypatch, make_item):
        _isolate_store(tmp_path, monkeypatch)
        monkeypatch.setenv("OPENAI_API_KEY", "cle-factice-ne-doit-jamais-servir")
        monkeypatch.setattr(
            ai.requests, "post",
            lambda *a, **k: pytest.fail("REPLAY ne doit jamais appeler OpenAI"),
        )
        item = make_item()
        store.save_items([item])
        store.save_incidents(runner.build_incidents([item]))

        context = runner.make_run_context(runner.MODE_REPLAY, as_of="2026-08-15T00:00:00+04:00")
        report = runner.execute(context, offline=True, persist=False)

        assert report.overall == "OK"
        assert report.ai_usage == {}

    def test_test_repeat_reste_offline_et_stable(self, make_item):
        items = [make_item(source_item_id="a"), make_item(source_item_id="b", org="Autre Organisation")]
        incidents_a = runner.build_incidents(items)
        incidents_b = runner.build_incidents(list(reversed(items)))
        from cyberwatch import identity
        assert identity.incidents_hash(incidents_a) == identity.incidents_hash(incidents_b)


def _isolate_store(tmp_path, monkeypatch):
    mapping = {
        "ITEMS_CSV": tmp_path / "items.csv",
        "INCIDENTS_CSV": tmp_path / "incidents.csv",
        "RUN_LOG_CSV": tmp_path / "run_log.csv",
        "RUN_SOURCES_CSV": tmp_path / "run_sources.csv",
        "SOURCES_CSV": tmp_path / "sources.csv",
        "ENTITY_WATCH_CSV": tmp_path / "entity_watch.csv",
        "AI_QUALIFICATIONS_CSV": tmp_path / "ai_qualifications.csv",
        "AI_USAGE_CSV": tmp_path / "ai_usage.csv",
        "SNAPSHOT_JSON": tmp_path / "snapshot.json",
        "BASELINE_JSON": tmp_path / "baseline.json",
        "SITE_DATA_DIR": tmp_path / "site-data",
    }
    for name, path in mapping.items():
        monkeypatch.setattr(store, name, path)


# --------------------------------------------------------------------------
# Sources
# --------------------------------------------------------------------------


class TestPerSourceBehavior:
    def test_cyberattaque_org_transmet_summary_et_content(self, make_item, monkeypatch):
        item = make_item(source="CYBERATTAQUE_ORG", threat=config.THREAT_UNKNOWN)
        entry = RawEntry(title="Titre", summary="Extrait", content="Corps complet de l'article.")
        captured = {}

        def fake_call(item_, entry_, spec_, requested, state_):
            captured["context"] = ai._context(entry_, state_.max_context_chars)
            return _payload(threat=_field("Ransomware"))

        monkeypatch.setattr(ai, "_call_openai", fake_call)
        spec = SourceSpec(source_id="CYBERATTAQUE_ORG", layer=config.LAYER_CORE, zone=config.LOC_FRANCE,
                           collector="cyberattaque_org", params={"include_content": True})

        ai.qualify_item(item, entry, spec, enabled_state())

        assert "Extrait" in captured["context"]
        assert "Corps complet de l'article." in captured["context"]

    def test_frenchbreaches_transmet_summary(self, make_item, monkeypatch):
        item = make_item(source="FRENCHBREACHES", threat=config.THREAT_UNKNOWN)
        entry = RawEntry(title="Titre", summary="Résumé RSS")
        captured = {}

        def fake_call(item_, entry_, spec_, requested, state_):
            captured["context"] = ai._context(entry_, state_.max_context_chars)
            return _payload(threat=_field("Ransomware"))

        monkeypatch.setattr(ai, "_call_openai", fake_call)
        ai.qualify_item(item, entry, SPEC, enabled_state())

        assert "Résumé RSS" in captured["context"]

    def test_ransomware_live_ne_requalifie_jamais_threat_ni_location_deja_structures(self, make_item, monkeypatch):
        item = make_item(source="RANSOMWARE_LIVE", threat="Ransomware", location="France métropolitaine",
                          sector=config.SECTOR_UNKNOWN)
        monkeypatch.setattr(
            ai, "_call_openai",
            lambda *a, **k: _payload(sector=_field("Industrie / Manufacture")),
        )
        spec = SourceSpec(source_id="RANSOMWARE_LIVE", layer=config.LAYER_CORE, zone="Multi",
                           collector="ransomware_live")

        ai.qualify_item(item, ENTRY, spec, enabled_state())

        assert item.Threat == "Ransomware"
        assert item.Location == "France métropolitaine"
        assert item.Sector == "Industrie / Manufacture"

    def test_source_marquee_skip_ai_qualification_est_exclue(self, make_item, monkeypatch):
        item = make_item(threat=config.THREAT_UNKNOWN)
        spec = SourceSpec(source_id="VEILLE_LLM", layer=config.LAYER_REGIONAL_WATCH, zone="Multi",
                           collector="veillellm", params={"skip_ai_qualification": True})
        monkeypatch.setattr(ai, "_call_openai", lambda *a, **k: pytest.fail("ne doit pas être appelé"))

        ai.qualify_item(item, ENTRY, spec, enabled_state())

        assert item.Threat == config.THREAT_UNKNOWN


# --------------------------------------------------------------------------
# Secret
# --------------------------------------------------------------------------


class TestSecretHandling:
    def test_absence_de_cle_desactive_sans_bloquer(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        state = ai.start_run()

        assert state.enabled is False

    def test_pipeline_continue_sans_appel_si_desactive(self, make_item, monkeypatch):
        item = make_item(threat=config.THREAT_UNKNOWN)
        state = ai.AiRunState(enabled=False)
        monkeypatch.setattr(ai, "_call_openai", lambda *a, **k: pytest.fail("désactivé : aucun appel attendu"))

        ai.qualify_item(item, ENTRY, SPEC, state)

        assert item.Threat == config.THREAT_UNKNOWN

    def test_aucun_secret_dans_la_ligne_ai_usage(self, make_item, monkeypatch):
        monkeypatch.setattr(
            ai, "_call_openai",
            lambda *a, **k: _payload(threat=_field("Ransomware")),
        )
        state = enabled_state(api_key="sk-test-tres-secret")
        item = make_item(threat=config.THREAT_UNKNOWN)
        ai.qualify_item(item, ENTRY, SPEC, state)

        row = ai.finish_run(state, "RUN-TEST", "2026-08-15T00:00:00+04:00", "MAJ")

        assert "sk-test-tres-secret" not in json.dumps(row)
        assert "sk-test-tres-secret" not in json.dumps(list(state.cache.values()))


class TestReportIntegration:
    def test_cmd_report_affiche_le_bloc_qualification_ia(self, tmp_path, monkeypatch, capsys):
        from types import SimpleNamespace
        from cyberwatch import cli

        _isolate_store(tmp_path, monkeypatch)
        store.append_run_log({
            "Run_ID": "RUN-TEST", "As_Of": "2026-08-15T00:00:00+04:00", "Mode": "MAJ",
            "Overall_Status": "OK", "Sources_OK": 1, "Sources_FAIL": 0,
        })
        store.append_ai_usage({
            "Run_ID": "RUN-TEST", "As_Of": "2026-08-15T00:00:00+04:00", "Mode": "MAJ",
            "Model": ai.DEFAULT_MODEL, "Prompt_Version": ai.PROMPT_VERSION,
            "Candidates": 3, "Cache_Hits": 1, "Calls_Attempted": 2, "Calls_Succeeded": 2,
            "Calls_Failed": 0, "Calls_Budget_Blocked": 0,
            "Threat_Unknown_Before": 1, "Threat_Qualified": 1,
            "Sector_Unknown_Before": 2, "Sector_Qualified": 2,
            "Location_Unknown_Before": 0, "Location_Qualified": 0,
            "Still_Unknown": 0, "Input_Tokens": 200, "Cached_Input_Tokens": 0,
            "Output_Tokens": 40, "Reasoning_Tokens": 0, "Total_Tokens": 240,
            "Estimated_Cost_USD": 0.000026, "Duration_s": 1.2, "Status": "OK",
        })

        assert cli.cmd_report(SimpleNamespace()) == 0
        output = capsys.readouterr().out

        assert "### Qualification IA" in output
        assert "Candidats : **3**" in output
        assert "Statut : **OK**" in output
