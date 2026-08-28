import csv
import json

from cyberwatch import dedup_ai, llm_runtime
from cyberwatch.dedup import STRONG_KEEP_REASON_CODES
from cyberwatch.duplicate_audit import (
    DedupAuditCandidate,
    MERGE_REVIEW_WEAK_CANONICAL_NAME,
    RISK_FALSE_MERGE,
    RISK_MISSED_DUPLICATE,
    find_daily_llm_candidates,
)


def _candidate(make_item, risk_type=RISK_MISSED_DUPLICATE, *, days=1, same_source=False, recurrence=False):
    left = make_item(
        source="A",
        org="Globex",
        published="2026-08-01",
        url="https://a",
        title="Globex revendiqué par Qilin",
    )
    right = make_item(
        source="A" if same_source else "B",
        org="Globex France",
        published=f"2026-08-{1 + days:02d}",
        url="https://b",
        title="Globex France frappé une nouvelle fois" if recurrence else "Globex France : cyberattaque",
    )
    return DedupAuditCandidate(
        risk_type=risk_type,
        left=left,
        right=right,
        days_apart=days,
        reason_code=MERGE_REVIEW_WEAK_CANONICAL_NAME,
    )


def test_same_day_cross_source_weak_merge_is_sent_to_llm(make_item):
    candidate = _candidate(
        make_item,
        risk_type=RISK_FALSE_MERGE,
        days=0,
    )
    assert dedup_ai.worth_challenging(candidate) is True


def test_same_source_false_merge_is_sent_to_llm(make_item):
    candidate = _candidate(
        make_item,
        risk_type=RISK_FALSE_MERGE,
        days=2,
        same_source=True,
    )
    assert dedup_ai.worth_challenging(candidate) is True


def test_same_day_recurrence_remains_auditable(make_item):
    candidate = _candidate(
        make_item,
        risk_type=RISK_FALSE_MERGE,
        days=0,
        recurrence=True,
    )
    assert dedup_ai.worth_challenging(candidate) is True


def test_classic_openai_call_uses_local_facts_and_cache(monkeypatch, tmp_path, make_item):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("DEDUP_AI_MAX_COST_USD", "1")
    cache_path = tmp_path / "dedup_ai_cache.csv"
    candidate = _candidate(make_item)
    facts = {
        candidate.left.Item_ID: {
            "Item_ID": candidate.left.Item_ID,
            "Victim_Website": "globex.example",
            "Threat_Actor": "Qilin",
        },
        candidate.right.Item_ID: {
            "Item_ID": candidate.right.Item_ID,
            "Victim_Website": "globex.example",
            "Threat_Actor": "Qilin",
        },
    }
    calls = []

    def fake_post(body, state):
        calls.append(body)
        assert "tools" not in body
        user_text = body["input"][1]["content"]
        assert "globex.example" in user_text
        assert "Qilin" in user_text
        return {
            "output_text": json.dumps({
                "same_organisation": "SAME",
                "same_incident": "SAME",
                "confidence": 0.97,
                "evidence": "Même domaine victime et même acteur.",
                "reason": "Les deux sources décrivent le même événement.",
            }),
            "usage": {
                "input_tokens": 100,
                "input_tokens_details": {"cached_tokens": 0},
                "output_tokens": 30,
                "output_tokens_details": {"reasoning_tokens": 0},
                "total_tokens": 130,
            },
        }

    monkeypatch.setattr(dedup_ai.ai, "_post_openai", fake_post)

    state = dedup_ai.start_run(cache_path)
    first = dedup_ai.challenge_candidate(candidate, facts, state)
    assert first.status == dedup_ai.STATUS_OK
    assert first.same_incident == dedup_ai.SAME
    assert state.calls_attempted == 1
    dedup_ai.save_cache(state)

    rows = list(csv.DictReader(cache_path.open(encoding="utf-8")))
    assert len(rows) == 1
    assert rows[0]["Same_Incident"] == "SAME"

    def should_not_call(*args, **kwargs):
        raise AssertionError("cache miss")

    monkeypatch.setattr(dedup_ai.ai, "_post_openai", should_not_call)
    cached_state = dedup_ai.start_run(cache_path)
    second = dedup_ai.challenge_candidate(candidate, facts, cached_state)
    assert second.status == dedup_ai.STATUS_CACHE_HIT
    assert second.cache_hit is True
    assert cached_state.calls_attempted == 0


def test_absent_api_key_disables_calls(monkeypatch, tmp_path, make_item):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    state = dedup_ai.start_run(tmp_path / "cache.csv")
    decision = dedup_ai.challenge_candidate(_candidate(make_item), {}, state)
    assert decision.status == dedup_ai.STATUS_DISABLED
    assert state.calls_attempted == 0


# --------------------------------------------------------------------------
# Batch quotidien (§Lot 3/4/17) : N candidats, au plus un appel LLM
# --------------------------------------------------------------------------


def _daily_candidate(make_item, index=0, *, days_apart="2026-01-01"):
    """Un candidat plausible et unique (§Lot 1 : concaténation exacte),
    jamais déjà résolu par un alias statique grâce au suffixe numérique."""
    left = make_item(
        source="A", org=f"Zorglub{index} Consulting",
        published="2026-08-01", url=f"https://new/{index}",
    )
    right = make_item(
        source="B", org=f"Zorglub{index}Consulting",
        published=days_apart, url=f"https://hist/{index}",
    )
    candidates = find_daily_llm_candidates([left], [left, right])
    assert len(candidates) == 1
    return candidates[0]


def _daily_state(monkeypatch, tmp_path, *, daily_max_candidates=40):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("DEDUP_AI_DAILY_ENABLED", "1")
    state = dedup_ai.start_run(tmp_path / "dedup_ai_daily_cache.csv")
    state.daily_max_candidates = daily_max_candidates
    return state


def _decision_payload(candidate, **overrides):
    payload = {
        "candidate_id": dedup_ai.candidate_id(candidate),
        "same_organisation": dedup_ai.SAME,
        "same_incident": dedup_ai.DIFFERENT,
        "confidence": 0.97,
        "matched_facts": ["compact_match"],
        "conflicting_facts": [],
        "evidence": "Même nom, avec ou sans espace.",
        "reason": "Variante typographique.",
    }
    payload.update(overrides)
    return payload


def test_batch_zero_candidate_zero_call(monkeypatch, tmp_path):
    def _forbidden(self, **kwargs):
        raise AssertionError("aucun appel LLM attendu sans candidat")

    monkeypatch.setattr(llm_runtime.LlmRuntime, "call_json", _forbidden)
    state = _daily_state(monkeypatch, tmp_path)
    decisions = dedup_ai.challenge_candidates_batch([], {}, state, {})
    assert decisions == {}
    assert state.batch_calls_attempted == 0
    assert dedup_ai.daily_status(state) == dedup_ai.DAILY_STATUS_NO_CANDIDATES


def test_batch_single_call(monkeypatch, tmp_path, make_item):
    candidates = [_daily_candidate(make_item, i) for i in range(3)]
    calls = []

    def fake_call_json(self, **kwargs):
        calls.append(kwargs)
        return llm_runtime.LlmCallResult(
            data={"decisions": [_decision_payload(c) for c in candidates]},
            usage=llm_runtime.LlmUsage(300, 0, 90, 0, 390, 0.002),
            duration_seconds=0.2, retries=0, model="gpt-4o-mini",
        )

    monkeypatch.setattr(llm_runtime.LlmRuntime, "call_json", fake_call_json)
    state = _daily_state(monkeypatch, tmp_path)
    decisions = dedup_ai.challenge_candidates_batch(candidates, {}, state, {})

    assert len(calls) == 1
    assert state.batch_calls_attempted == 1
    assert state.calls_attempted == 1
    assert len(decisions) == 3
    assert all(d.status == dedup_ai.STATUS_OK for d in decisions.values())
    assert all(d.same_organisation == dedup_ai.SAME for d in decisions.values())
    assert dedup_ai.daily_status(state) == dedup_ai.DAILY_STATUS_OK


def test_batch_capacity_limit(monkeypatch, tmp_path, make_item):
    """5 candidats mais une capacité de 2 : un seul appel, 3 candidats
    explicitement marqués NOT_REVIEWED_CAPACITY (jamais silencieusement
    ignorés, jamais un second appel, §Lot 4/15)."""
    candidates = [_daily_candidate(make_item, i) for i in range(5)]
    calls = []

    def fake_call_json(self, **kwargs):
        calls.append(kwargs)
        # Seuls les deux premiers candidats (par priorité de signal) sont
        # transmis dans le contenu utilisateur : on ne répond que pour eux.
        content = kwargs["user_content"]
        sent_ids = [dedup_ai.candidate_id(c) for c in candidates if dedup_ai.candidate_id(c) in content]
        return llm_runtime.LlmCallResult(
            data={"decisions": [_decision_payload(c) for c in candidates
                                 if dedup_ai.candidate_id(c) in sent_ids]},
            usage=llm_runtime.LlmUsage(200, 0, 60, 0, 260, 0.0015),
            duration_seconds=0.2, retries=0, model="gpt-4o-mini",
        )

    monkeypatch.setattr(llm_runtime.LlmRuntime, "call_json", fake_call_json)
    state = _daily_state(monkeypatch, tmp_path, daily_max_candidates=2)
    decisions = dedup_ai.challenge_candidates_batch(candidates, {}, state, {})

    assert len(calls) == 1
    assert state.batch_calls_attempted == 1
    not_reviewed = [d for d in decisions.values() if d.status == dedup_ai.STATUS_NOT_REVIEWED_CAPACITY]
    assert len(not_reviewed) == 3
    assert state.candidates_not_reviewed_capacity == 3
    assert dedup_ai.daily_summary(state)["dedup_candidates_not_reviewed_capacity"] == 3


def test_budget_par_defaut_absorbe_un_run_maj_realiste(monkeypatch, tmp_path):
    """Cas réel constaté sur RUN-20260825T084327 : 428 candidats générés par
    une MAJ à recouvrement de 21 jours, mais 8000 caractères n'en laissaient
    passer que 4 avant capacité — 3 doublons réels confirmés (Capgemini,
    Netim, Intermarché) sont restés parmi les 424 non revus. Le budget par
    défaut doit être assez grand pour ne plus être le facteur limitant sur un
    run de cette taille."""
    monkeypatch.delenv("DEDUP_AI_MAX_CONTEXT_CHARS", raising=False)
    state = dedup_ai.start_run(tmp_path / "dedup_ai_daily_cache.csv")
    assert state.max_context_chars >= 40000


def test_prompt_calibre_le_poids_du_nom_et_des_ecarts_numeriques():
    """Cas réel constaté (audit 2026-08-25) : "Banque Alimentaire de la
    Croix-Rouge à Strasbourg" / "Banque Alimentaire de Strasbourg", même
    date, noms quasi identiques (score flou 0.82), a été jugé DIFFERENT par
    le seul motif "Affected_Count: 10073 vs 10000" — un artefact d'arrondi
    entre deux sources, pas un vrai conflit. Sans contrepoids explicite au
    principe de prudence existant, tout écart visible se lit comme un
    doute. Le prompt doit désormais dire explicitement que (a) nom quasi
    identique + date très proche est une preuve forte de same_organisation,
    et (b) un chiffre rond face à un chiffre précis du même ordre de
    grandeur n'est pas un signal de conflit."""
    prompt = dedup_ai.BATCH_SYSTEM_PROMPT
    assert "date de publication identique ou tres proche" in prompt
    assert "preuve forte de same_organisation" in prompt
    assert "chiffre rond" in prompt
    assert "meme ordre de grandeur" in prompt
    # Le principe de prudence reste explicite : ce n'est pas un
    # contournement codé en dur, seulement une recalibration de ce qui
    # compte comme doute réel pour le LLM.
    assert "Une fusion abusive est plus grave qu'un doublon laisse separe" in prompt


def test_confidence_schema_precise_ce_qu_elle_mesure():
    """Root cause distincte trouvée en creusant le cas ci-dessus : la
    confiance renvoyée par le modèle pour le verdict DIFFERENT (0.8169)
    correspondait exactement au fuzzy_score de sélection du candidat, déjà
    visible dans signals.fuzzy_score — sans description dans le schéma,
    rien n'empêchait le modèle de recopier ce signal d'entrée plutôt que
    d'exprimer sa propre certitude sur son verdict."""
    schema = dedup_ai._batch_schema()
    confidence = schema["properties"]["decisions"]["items"]["properties"]["confidence"]
    assert confidence.get("description")
    assert "fuzzy_score" in confidence["description"]


def test_batch_schema_validation(monkeypatch, tmp_path, make_item):
    """Une valeur hors énumération invalide uniquement la décision concernée,
    sans faire planter le batch entier."""
    good = _daily_candidate(make_item, 0)
    bad = _daily_candidate(make_item, 1)

    def fake_call_json(self, **kwargs):
        return llm_runtime.LlmCallResult(
            data={"decisions": [
                _decision_payload(good),
                _decision_payload(bad, same_organisation="MAYBE"),
            ]},
            usage=llm_runtime.LlmUsage(100, 0, 40, 0, 140, 0.001),
            duration_seconds=0.1, retries=0, model="gpt-4o-mini",
        )

    monkeypatch.setattr(llm_runtime.LlmRuntime, "call_json", fake_call_json)
    state = _daily_state(monkeypatch, tmp_path)
    decisions = dedup_ai.challenge_candidates_batch([good, bad], {}, state, {})

    assert decisions[dedup_ai.candidate_id(good)].status == dedup_ai.STATUS_OK
    assert decisions[dedup_ai.candidate_id(bad)].status == dedup_ai.STATUS_ERROR
    assert state.batch_calls_attempted == 1


def test_same_incident_requires_same_org_in_batch(monkeypatch, tmp_path, make_item):
    candidate = _daily_candidate(make_item, 0)

    def fake_call_json(self, **kwargs):
        return llm_runtime.LlmCallResult(
            data={"decisions": [_decision_payload(
                candidate, same_organisation=dedup_ai.DIFFERENT, same_incident=dedup_ai.SAME,
            )]},
            usage=llm_runtime.LlmUsage(100, 0, 40, 0, 140, 0.001),
            duration_seconds=0.1, retries=0, model="gpt-4o-mini",
        )

    monkeypatch.setattr(llm_runtime.LlmRuntime, "call_json", fake_call_json)
    state = _daily_state(monkeypatch, tmp_path)
    decisions = dedup_ai.challenge_candidates_batch([candidate], {}, state, {})

    assert decisions[dedup_ai.candidate_id(candidate)].status == dedup_ai.STATUS_ERROR


def test_batch_missing_decision_for_a_candidate_id_is_an_error(monkeypatch, tmp_path, make_item):
    good = _daily_candidate(make_item, 0)
    missing = _daily_candidate(make_item, 1)

    def fake_call_json(self, **kwargs):
        return llm_runtime.LlmCallResult(
            data={"decisions": [_decision_payload(good)]},  # `missing` absent de la réponse
            usage=llm_runtime.LlmUsage(100, 0, 40, 0, 140, 0.001),
            duration_seconds=0.1, retries=0, model="gpt-4o-mini",
        )

    monkeypatch.setattr(llm_runtime.LlmRuntime, "call_json", fake_call_json)
    state = _daily_state(monkeypatch, tmp_path)
    decisions = dedup_ai.challenge_candidates_batch([good, missing], {}, state, {})

    assert decisions[dedup_ai.candidate_id(good)].status == dedup_ai.STATUS_OK
    assert decisions[dedup_ai.candidate_id(missing)].status == dedup_ai.STATUS_ERROR


def test_batch_cache_hit_skips_second_call(monkeypatch, tmp_path, make_item):
    """§Lot 13 : une décision déjà en cache pour la paire exacte (payload,
    signaux, modèle, prompt/schema version) n'est jamais renvoyée au modèle,
    y compris depuis un nouveau `DedupAiRunState` (persistance réelle entre
    deux runs)."""
    candidate = _daily_candidate(make_item, 0)
    cache_path = tmp_path / "dedup_ai_daily_cache.csv"
    calls = []

    def fake_call_json(self, **kwargs):
        calls.append(kwargs)
        return llm_runtime.LlmCallResult(
            data={"decisions": [_decision_payload(candidate)]},
            usage=llm_runtime.LlmUsage(100, 0, 40, 0, 140, 0.001),
            duration_seconds=0.1, retries=0, model="gpt-4o-mini",
        )

    monkeypatch.setattr(llm_runtime.LlmRuntime, "call_json", fake_call_json)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("DEDUP_AI_DAILY_ENABLED", "1")

    first_state = dedup_ai.start_run(cache_path)
    first = dedup_ai.challenge_candidates_batch([candidate], {}, first_state, {})
    assert first[dedup_ai.candidate_id(candidate)].status == dedup_ai.STATUS_OK
    assert len(calls) == 1
    dedup_ai.save_cache(first_state)

    def should_not_call(self, **kwargs):
        raise AssertionError("cache miss : ne devrait jamais rappeler le modèle")

    monkeypatch.setattr(llm_runtime.LlmRuntime, "call_json", should_not_call)
    second_state = dedup_ai.start_run(cache_path)
    second = dedup_ai.challenge_candidates_batch([candidate], {}, second_state, {})
    assert second[dedup_ai.candidate_id(candidate)].status == dedup_ai.STATUS_CACHE_HIT
    assert second_state.batch_calls_attempted == 0
    assert len(calls) == 1


# --------------------------------------------------------------------------
# validate_ai_dedup_decision (§Lot 5/17) : politique d'application déterministe
# --------------------------------------------------------------------------


def test_validate_applies_high_confidence_same_organisation(make_item):
    left = make_item(source="A", org="Zorglub9 Consulting", published="2026-08-01", url="https://a")
    right = make_item(source="B", org="Zorglub9Consulting", published="2026-01-01", url="https://b")
    candidates = find_daily_llm_candidates([left], [left, right])
    candidate = candidates[0]
    decision = dedup_ai.DedupAiDecision(
        status=dedup_ai.STATUS_OK, same_organisation=dedup_ai.SAME,
        same_incident=dedup_ai.DIFFERENT, confidence=0.97, evidence="e",
    )
    proposal = dedup_ai.validate_ai_dedup_decision(candidate, decision, model="gpt-4o-mini")
    assert proposal is not None
    assert proposal["Decision"] == "SAME"
    assert proposal["Origin"] == "LLM_CONFIRMED"
    assert {proposal["Alias_Key"], proposal["Canonical_Key"]} == {
        "zorglub9 consulting", "zorglub9consulting",
    }


def test_validate_applies_confidence_juste_au_dessus_du_seuil(make_item):
    """Cas réel constaté (reset 2026-08-25, "Banque Alimentaire de la
    Croix-Rouge à Strasbourg" / "Banque Alimentaire de Strasbourg") : le
    filet a jugé SAME/SAME avec 5 faits concordants mais seulement 0.90 de
    confiance. L'ancien seuil de 0.95 rejetait cette décision correcte, le
    registre d'identité n'était jamais écrit, et le doublon était publié."""
    left = make_item(source="A", org="Zorglub6 Consulting", published="2026-08-01", url="https://a")
    right = make_item(source="B", org="Zorglub6Consulting", published="2026-01-01", url="https://b")
    candidate = find_daily_llm_candidates([left], [left, right])[0]
    decision = dedup_ai.DedupAiDecision(
        status=dedup_ai.STATUS_OK, same_organisation=dedup_ai.SAME,
        same_incident=dedup_ai.SAME, confidence=0.90, evidence="e",
    )
    proposal = dedup_ai.validate_ai_dedup_decision(candidate, decision, model="gpt-4o-mini")
    assert proposal is not None
    assert proposal["Decision"] == "SAME"


def test_validate_rejects_low_confidence(make_item):
    left = make_item(source="A", org="Zorglub8 Consulting", published="2026-08-01", url="https://a")
    right = make_item(source="B", org="Zorglub8Consulting", published="2026-01-01", url="https://b")
    candidate = find_daily_llm_candidates([left], [left, right])[0]
    decision = dedup_ai.DedupAiDecision(
        status=dedup_ai.STATUS_OK, same_organisation=dedup_ai.SAME,
        same_incident=dedup_ai.UNKNOWN, confidence=0.80, evidence="e",
    )
    assert dedup_ai.validate_ai_dedup_decision(candidate, decision) is None


def test_validate_rejects_different_and_unknown(make_item):
    left = make_item(source="A", org="Zorglub7 Consulting", published="2026-08-01", url="https://a")
    right = make_item(source="B", org="Zorglub7Consulting", published="2026-01-01", url="https://b")
    candidate = find_daily_llm_candidates([left], [left, right])[0]
    for same_organisation in (dedup_ai.DIFFERENT, dedup_ai.UNKNOWN):
        decision = dedup_ai.DedupAiDecision(
            status=dedup_ai.STATUS_OK, same_organisation=same_organisation,
            confidence=0.99, evidence="e",
        )
        assert dedup_ai.validate_ai_dedup_decision(candidate, decision) is None


def test_validate_incident_decision_persists_final_verdict(make_item):
    left = make_item(source="A", org="Globex", published="2026-08-01", url="https://a")
    right = make_item(source="B", org="Globex", published="2026-08-01", url="https://b")
    candidate = find_daily_llm_candidates([left], [left, right])[0]
    decision = dedup_ai.DedupAiDecision(
        status=dedup_ai.STATUS_OK,
        same_organisation=dedup_ai.SAME,
        same_incident=dedup_ai.DIFFERENT,
        confidence=0.93,
        evidence="Impacts distincts.",
        matched_facts=("même victime",),
        conflicting_facts=("acteurs différents",),
    )

    proposal = dedup_ai.validate_ai_incident_decision(candidate, decision, now="2026-08-28")

    assert proposal is not None
    assert proposal["Decision"] == dedup_ai.DIFFERENT
    assert json.loads(proposal["Matched_Facts_JSON"]) == ["même victime"]
    assert json.loads(proposal["Conflicting_Facts_JSON"]) == ["acteurs différents"]


def test_validate_incident_same_cannot_override_strong_veto(make_item):
    left = make_item(
        source="A", source_item_id="one", org="Globex",
        published="2026-08-01", url="https://a",
    )
    right = make_item(
        source="A", source_item_id="two", org="Globex",
        published="2026-08-01", url="https://b",
    )
    candidate = DedupAuditCandidate(
        risk_type=RISK_FALSE_MERGE,
        left=left,
        right=right,
        days_apart=0,
        reason_code=MERGE_REVIEW_WEAK_CANONICAL_NAME,
    )
    decision = dedup_ai.DedupAiDecision(
        status=dedup_ai.STATUS_OK,
        same_organisation=dedup_ai.SAME,
        same_incident=dedup_ai.SAME,
        confidence=0.99,
        evidence="e",
    )

    assert dedup_ai.validate_ai_incident_decision(candidate, decision) is None


def test_recurrence_veto_does_not_block_organisation_identity(make_item):
    """Deux événements distincts peuvent viser la même organisation.

    Le veto de récurrence protège la fusion d'incident, pas l'identité de la
    victime ; les deux décisions ne doivent plus être confondues.
    """
    left = make_item(
        source="A", org="Zorglub6 Consulting", published="2026-08-01",
        url="https://a", title="Zorglub6 Consulting revendiqué",
    )
    right = make_item(
        source="A", org="Zorglub6Consulting", published="2026-08-03",
        url="https://b", title="Zorglub6Consulting frappé une nouvelle fois",
    )
    from cyberwatch.dedup import decide_merge
    veto = decide_merge(left, right)
    assert veto.reason_code in STRONG_KEEP_REASON_CODES

    candidate = DedupAuditCandidate(
        risk_type=RISK_MISSED_DUPLICATE, left=left, right=right,
        days_apart=2, reason_code="DUPLICATE_CANDIDATE_DAILY_LLM",
    )
    decision = dedup_ai.DedupAiDecision(
        status=dedup_ai.STATUS_OK, same_organisation=dedup_ai.SAME,
        same_incident=dedup_ai.DIFFERENT, confidence=0.99, evidence="e",
    )
    assert dedup_ai.validate_ai_dedup_decision(candidate, decision) is not None
    incident = dedup_ai.validate_ai_incident_decision(candidate, decision)
    assert incident is not None
    assert incident["Decision"] == dedup_ai.DIFFERENT


def test_llm_cannot_override_conflicting_event_date(make_item, monkeypatch):
    """`INCIDENT_KEEP_CONFLICTING_EVENT_DATE` ne se déclenche, dans
    `decide_merge`, qu'une fois les deux items déjà de même identité
    organisationnelle (il vient après le test d'égalité des clés) : le vrai
    test n'est donc pas au moment de la proposition (comme pour la
    récurrence), mais après application (§Lot 9) — le moteur déterministe
    reste seul juge de la fusion d'incident, même une fois l'identité
    unifiée par une décision LLM persistée. Deux `Event_Date` incompatibles
    restent un veto fort, jamais contourné."""
    from cyberwatch import org_identity
    from cyberwatch.dedup import NO_DECISION, decide_merge, group_components

    left = make_item(
        source="A", org="Zorglub5 Consulting", published="2026-08-01",
        event="2026-07-01", url="https://a",
    )
    right = make_item(
        source="B", org="Zorglub5Consulting", published="2026-08-03",
        event="2026-07-15", url="https://b",
    )

    # Avant toute décision d'identité : clés distinctes, rien à contourner.
    assert decide_merge(left, right).action == NO_DECISION

    # Simule une décision LLM validée et persistée dans le registre (comme le
    # ferait `runner.run_daily_dedup_net` avant de reconstruire les incidents).
    monkeypatch.setitem(
        org_identity.ORGANISATION_IDENTITY_REGISTRY,
        "zorglub5consulting", "zorglub5 consulting",
    )
    left_key = org_identity.effective_organisation_key(left.Organisation_Raw, left.Organisation_Key)
    right_key = org_identity.effective_organisation_key(right.Organisation_Raw, right.Organisation_Key)
    assert left_key == right_key, "l'identité organisationnelle doit maintenant être unifiée"

    veto = decide_merge(left, right)
    assert veto.reason_code == "INCIDENT_KEEP_CONFLICTING_EVENT_DATE"
    assert veto.reason_code in STRONG_KEEP_REASON_CODES

    components = group_components([left, right])
    assert len(components) == 2, "les deux items restent deux incidents distincts malgré l'identité unifiée"
