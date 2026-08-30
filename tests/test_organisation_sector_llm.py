from __future__ import annotations

import json

import pytest

from cyberwatch import config, enrichment, llm_runtime, org_identity, organisation_sector as osec, store
from cyberwatch import organisation_sector_llm as osl


@pytest.fixture(autouse=True)
def _isolate_data_dir(monkeypatch, tmp_path):
    """Jamais d'écriture dans data/ réel : organisation_sector(_llm) dérive
    tous ses chemins auxiliaires (dont le cache LLM) de store.ITEMS_CSV."""
    monkeypatch.setattr(store, "ITEMS_CSV", tmp_path / "items.csv")


class _Response:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


def _payload(data, *, input_tokens=100, output_tokens=20):
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


def _reference(key, organisation, sector):
    return {
        key: enrichment.Enrichment(
            organisation=organisation, sector=sector, location="", scope="France",
            reason="validation humaine", validation_url="https://acme.example/about",
        )
    }


def _context(key="acme", organisation="Acme"):
    return osl.OrganisationContext(organisation_key=key, organisation=organisation)


def _enable_llm(monkeypatch, fake_post):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(llm_runtime, "_RUNTIME", llm_runtime.LlmRuntime())
    monkeypatch.setattr(llm_runtime.requests, "post", fake_post)


# --------------------------------------------------------------------------
# Batching déterministe (§16)
# --------------------------------------------------------------------------


def test_build_batches_is_deterministic_and_stable_order():
    entries = list(range(95))
    batches = osl.build_batches(entries, batch_size=40)
    assert [len(b) for b in batches] == [40, 40, 15]
    assert batches[0][0] == 0
    assert batches[-1][-1] == 94
    # Rejouer avec le même batch_size donne exactement le même découpage.
    again = osl.build_batches(entries, batch_size=40)
    assert batches == again


def test_select_organisations_for_llm_excludes_confirmed_and_conflict(make_item):
    confirmed_item = make_item(org="Acme", sector=config.SECTOR_UNKNOWN)
    unknown_item = make_item(source_item_id="2", org="Autre Orga", sector=config.SECTOR_UNKNOWN, url="https://example.org/b")
    reference = _reference(confirmed_item.Organisation_Key, "Acme", config.SECTOR_SERVICES)
    items = [confirmed_item, unknown_item]
    decisions = osec.resolve_all_organisation_sectors(items, reference=reference)
    selected = osl.select_organisations_for_llm(items, decisions)
    assert confirmed_item.Organisation_Key not in selected
    assert unknown_item.Organisation_Key in selected
    # Une organisation n'apparaît qu'une seule fois.
    assert len(selected) == len(set(selected))


# --------------------------------------------------------------------------
# Cache et Input_Hash (§18)
# --------------------------------------------------------------------------


def test_input_hash_changes_with_prompt_version_model_and_taxonomy(monkeypatch):
    context = _context()
    base = osl.compute_input_hash(context, model="gpt-5-nano", prompt_version="v1")
    same = osl.compute_input_hash(context, model="gpt-5-nano", prompt_version="v1")
    assert base == same

    different_prompt = osl.compute_input_hash(context, model="gpt-5-nano", prompt_version="v2")
    assert different_prompt != base

    different_model = osl.compute_input_hash(context, model="gpt-4o", prompt_version="v1")
    assert different_model != base

    monkeypatch.setattr(config, "SECTORS", config.SECTORS + ["Nouveau Secteur"])
    different_taxonomy = osl.compute_input_hash(context, model="gpt-5-nano", prompt_version="v1")
    assert different_taxonomy != base


def test_context_keeps_at_least_one_evidence_per_produced_channel(make_item):
    item = make_item(org="Acme", sector=config.SECTOR_UNKNOWN)
    evidence = [
        osec.OrganisationSectorEvidence(
            item.Organisation_Key, "Acme", config.SECTOR_TECH,
            osec.EVIDENCE_SOURCE_ACTIVITY, "MEDIUM",
            source=f"article:{index}", evidence_text=f"preuve {index}",
        )
        for index in range(20)
    ]
    evidence.append(osec.OrganisationSectorEvidence(
        item.Organisation_Key, "Acme", config.SECTOR_SERVICES,
        osec.EVIDENCE_DOMAIN_PAGE, "MEDIUM",
        source="domain_page", evidence_text="cabinet de conseil",
    ))

    context = osl.build_organisation_context(
        item.Organisation_Key, [item], source_fact_rows=[], org_cache_rows=[],
        evidence=evidence,
    )

    assert {value["type"] for value in context.evidence_details} >= {
        osec.EVIDENCE_SOURCE_ACTIVITY, osec.EVIDENCE_DOMAIN_PAGE,
    }


def test_identity_aliases_share_evidence_and_one_final_decision(make_item, monkeypatch):
    alias = make_item(
        org="Eusko", sector=config.SECTOR_UNKNOWN, source="CYBERATTAQUE_ORG",
    )
    canonical = make_item(
        source_item_id="2", org="Euskal Moneta", sector=config.SECTOR_UNKNOWN,
        source="FRENCHBREACHES", url="https://example.org/euskal-moneta",
    )
    monkeypatch.setattr(
        org_identity, "ORGANISATION_IDENTITY_REGISTRY",
        {alias.Organisation_Key: canonical.Organisation_Key},
    )
    facts = [
        {
            "Item_ID": alias.Item_ID,
            "Activity_Description": "gestion de la monnaie locale Eusko",
            "Activity_Sector_Match": config.SECTOR_CULTURE,
        },
        {
            "Item_ID": canonical.Item_ID,
            "Activity_Description": "monnaie locale complémentaire basque",
            "Activity_Sector_Match": config.SECTOR_FINANCE,
        },
    ]
    items = [alias, canonical]

    evidence = osec.collect_organisation_evidence(
        items, reference={}, source_fact_rows=facts, org_cache_rows=[],
        llm_cache_rows=[], domain_page_rows=[],
    )
    assert set(evidence) == {canonical.Organisation_Key}
    assert {value.sector for value in evidence[canonical.Organisation_Key]} == {
        config.SECTOR_CULTURE, config.SECTOR_FINANCE,
    }

    decisions = osec.resolve_all_organisation_sectors(
        items, reference={}, source_fact_rows=facts, org_cache_rows=[],
        llm_cache_rows=[], domain_page_rows=[],
    )
    assert osl.select_organisations_for_llm(items, decisions) == [canonical.Organisation_Key]
    context = osl.build_organisation_context(
        canonical.Organisation_Key, items, source_fact_rows=facts,
        org_cache_rows=[], evidence=evidence[canonical.Organisation_Key],
    )
    assert set(context.aliases) == {"Eusko", "Euskal Moneta"}
    assert set(context.source_ids) == {"CYBERATTAQUE_ORG", "FRENCHBREACHES"}
    assert set(context.activity_descriptions) == {
        "gestion de la monnaie locale Eusko",
        "monnaie locale complémentaire basque",
    }

    final = osec.resolve_all_organisation_sectors(
        items, reference={}, source_fact_rows=facts, org_cache_rows=[],
        domain_page_rows=[], llm_cache_rows=[{
            "Organisation_Key": canonical.Organisation_Key,
            "Organisation": "Euskal Moneta",
            "Sector": config.SECTOR_FINANCE,
            "Confidence": "0.90",
            "Model": "gpt-5-nano",
            "Reason": "activité de gestion d'une monnaie locale",
        }],
    )
    changed, _provenance = osec.apply_organisation_sector_decisions(items, final)
    assert changed == 2
    assert {item.Sector for item in items} == {config.SECTOR_FINANCE}


def test_cache_hit_avoids_any_llm_call(make_item, monkeypatch, tmp_path):
    """Revirement de politique (audit 2026-08-26) : un candidat déjà en
    cache résout désormais l'organisation en CONFIRMED (appliqué), pas
    seulement TENTATIVE — elle n'est donc plus du tout sélectionnée par
    select_organisations_for_llm (déjà résolue), et jamais seulement un
    "cache hit" parmi d'autres candidats sélectionnés. Dans les deux cas,
    la garantie qui compte reste la même : aucun appel LLM n'est fait."""
    item = make_item(org="Acme", sector=config.SECTOR_UNKNOWN)
    items = [item]
    context = osl.build_organisation_context(
        item.Organisation_Key, items, source_fact_rows=[], org_cache_rows=[],
    )
    input_hash = osl.compute_input_hash(context, model="gpt-5-nano", prompt_version=osl.PROMPT_VERSION)
    cache_rows = [{
        "Organisation_Key": item.Organisation_Key,
        "Organisation": "Acme",
        "Input_Hash": input_hash,
        "Sector": config.SECTOR_TECH,
        "Confidence": "0.90",
        "Basis": "name_semantics",
        "Reason": "raison",
        "Model": "gpt-5-nano",
        "Prompt_Version": osl.PROMPT_VERSION,
        "Created_At": "2026-01-01T00:00:00Z",
    }]

    called = {"count": 0}

    def fake_post(url, *, json, headers, timeout):
        called["count"] += 1
        return _Response(payload=_payload({"organisations": []}))

    _enable_llm(monkeypatch, fake_post)
    report = osl.enrich_unknown_organisation_sectors(
        items, reference={}, source_fact_rows=[], org_cache_rows=[], cache_rows=cache_rows,
    )
    assert called["count"] == 0
    assert report.organisations_selected == 1
    assert report.cache_hits == 1
    assert report.cache_misses == 0
    assert report.calls == 0


def _legacy_cache_row(osl, context, *, sector, basis="explicit_activity", confidence="0.90"):
    prompt = "2026-08-28.8"
    model = "gpt-5-nano"
    return {
        "Organisation_Key": context.organisation_key,
        "Organisation": context.organisation,
        "Input_Hash": osl._legacy_compatible_input_hash(context, model=model, prompt_version=prompt),
        "Sector": sector,
        "Confidence": confidence,
        "Basis": basis,
        "Reason": "décision historique corroborée",
        "Model": model,
        "Prompt_Version": prompt,
        "Created_At": "2026-08-30T11:03:45+00:00",
    }


def test_legacy_positive_cache_is_migrated_when_business_context_is_identical(make_item):
    item = make_item(org="Easypara", sector=config.SECTOR_UNKNOWN)
    facts = [{
        "Item_ID": item.Item_ID,
        "Activity_Description": "vente en ligne de produits",
        "Activity_Sector_Match": config.SECTOR_RETAIL,
    }]
    evidence = osec.collect_organisation_evidence(
        [item], reference={}, source_fact_rows=facts, org_cache_rows=[],
        domain_page_rows=[], llm_cache_rows=[],
    )
    context = osl.build_organisation_context(
        item.Organisation_Key, [item], source_fact_rows=facts, org_cache_rows=[],
        evidence=evidence[item.Organisation_Key],
    )
    legacy = _legacy_cache_row(osl, context, sector=config.SECTOR_RETAIL)

    report = osl.enrich_unknown_organisation_sectors(
        [item], reference={}, source_fact_rows=facts, org_cache_rows=[],
        domain_page_rows=[], cache_rows=[legacy], no_llm=True, persist=False,
    )

    assert report.cache_hits == 1
    assert report.compatible_cache_hits == 1
    assert report.cache_misses == 0
    assert report.outcomes[item.Organisation_Key] == "PRODUCED"
    row = report.cache_rows[0]
    assert row["Sector"] == config.SECTOR_RETAIL
    assert row["Prompt_Version"] == osl.PROMPT_VERSION
    assert row["Decision_Status"] == "PRODUCED"
    assert row["Execution_Status"] == "CACHE_COMPATIBLE_REUSE"
    assert row["Input_Hash"] == osl.compute_input_hash(
        context, model="gpt-5-nano", prompt_version=osl.PROMPT_VERSION,
    )


def test_legacy_cache_is_not_migrated_when_context_changed(make_item):
    item = make_item(org="Easypara", sector=config.SECTOR_UNKNOWN)
    old_facts = [{
        "Item_ID": item.Item_ID,
        "Activity_Description": "vente en ligne de produits",
        "Activity_Sector_Match": config.SECTOR_RETAIL,
    }]
    old_evidence = osec.collect_organisation_evidence(
        [item], reference={}, source_fact_rows=old_facts, org_cache_rows=[],
        domain_page_rows=[], llm_cache_rows=[],
    )
    old_context = osl.build_organisation_context(
        item.Organisation_Key, [item], source_fact_rows=old_facts, org_cache_rows=[],
        evidence=old_evidence[item.Organisation_Key],
    )
    legacy = _legacy_cache_row(osl, old_context, sector=config.SECTOR_RETAIL)
    new_facts = [{
        "Item_ID": item.Item_ID,
        "Activity_Description": "service de télémédecine",
        "Activity_Sector_Match": config.SECTOR_HEALTH,
    }]

    report = osl.enrich_unknown_organisation_sectors(
        [item], reference={}, source_fact_rows=new_facts, org_cache_rows=[],
        domain_page_rows=[], cache_rows=[legacy], no_llm=True, persist=False,
    )
    assert report.compatible_cache_hits == 0
    assert report.cache_misses == 1
    assert report.cache_rows == []


def test_legacy_multiple_signals_requires_consistent_sector_support():
    conflicting = osl.OrganisationContext(
        organisation_key="zero logement vacant",
        organisation="Zéro Logement Vacant",
        evidence_types=("source_activity",),
        evidence_details=(
            {"type": "source_activity", "sector": config.SECTOR_ADMIN, "text": "service public"},
            {"type": "source_activity", "sector": config.SECTOR_TECH, "text": "service numérique de l'État"},
        ),
    )
    candidate = osl.LlmOrganisationCandidate(
        "zero logement vacant", config.SECTOR_ADMIN, 0.78, "multiple_signals", "historique",
    )
    assert not osl._legacy_candidate_has_current_support(conflicting, candidate)

    aligned = osl.OrganisationContext(
        organisation_key="ultra premium direct",
        organisation="Ultra Premium Direct",
        evidence_types=("source_activity",),
        evidence_details=(
            {"type": "source_activity", "sector": osec.SECTOR_AGRICULTURE, "text": "alimentation pour chiens et chats"},
            {"type": "source_activity", "sector": osec.SECTOR_AGRICULTURE, "text": "spécialiste français de l'alimentation animale"},
        ),
    )
    aligned_candidate = osl.LlmOrganisationCandidate(
        "ultra premium direct", osec.SECTOR_AGRICULTURE, 0.92, "multiple_signals", "historique",
    )
    assert osl._legacy_candidate_has_current_support(aligned, aligned_candidate)


def test_legacy_explicit_activity_rejects_conflicting_sector_evidence():
    context = osl.OrganisationContext(
        organisation_key="example",
        organisation="Example",
        evidence_types=("source_activity",),
        evidence_details=(
            {"type": "source_activity", "sector": config.SECTOR_RETAIL, "text": "vente en ligne"},
            {"type": "source_activity", "sector": config.SECTOR_TECH, "text": "plateforme logicielle"},
        ),
    )
    candidate = osl.LlmOrganisationCandidate(
        "example", config.SECTOR_RETAIL, 0.80, "explicit_activity", "historique",
    )
    assert not osl._legacy_candidate_has_current_support(context, candidate)


def test_legacy_services_cache_for_social_context_requires_fresh_decision(make_item):
    item = make_item(org="Association Exemple", sector=config.SECTOR_UNKNOWN)
    facts = [{
        "Item_ID": item.Item_ID,
        "Activity_Description": "association caritative d'aide alimentaire",
        "Activity_Sector_Match": config.SECTOR_SERVICES,
    }]
    evidence = osec.collect_organisation_evidence(
        [item], reference={}, source_fact_rows=facts, org_cache_rows=[],
        domain_page_rows=[], llm_cache_rows=[],
    )
    context = osl.build_organisation_context(
        item.Organisation_Key, [item], source_fact_rows=facts, org_cache_rows=[],
        evidence=evidence[item.Organisation_Key],
    )
    legacy = _legacy_cache_row(osl, context, sector=config.SECTOR_SERVICES)
    report = osl.enrich_unknown_organisation_sectors(
        [item], reference={}, source_fact_rows=facts, org_cache_rows=[],
        domain_page_rows=[], cache_rows=[legacy], no_llm=True, persist=False,
    )
    assert report.compatible_cache_hits == 0
    assert report.cache_misses == 1
    assert report.cache_rows == []


def test_stale_cache_is_a_miss_and_is_not_reinjected(make_item):
    item = make_item(org="Acme", sector=config.SECTOR_UNKNOWN)
    stale = [{
        "Organisation_Key": item.Organisation_Key,
        "Organisation": "Acme",
        "Input_Hash": "obsolete",
        "Sector": config.SECTOR_HEALTH,
        "Confidence": "0.90",
        "Basis": "name_semantics",
        "Reason": "ancienne décision",
        "Model": "gpt-5-nano",
        "Prompt_Version": "ancienne-version",
        "Created_At": "2026-01-01T00:00:00Z",
    }]

    report = osl.enrich_unknown_organisation_sectors(
        [item], reference={}, source_fact_rows=[], org_cache_rows=[],
        cache_rows=stale, no_llm=True, persist=False,
    )

    assert report.organisations_selected == 1
    assert report.cache_hits == 0
    assert report.cache_misses == 1
    assert report.cache_rows == []


def test_cache_miss_triggers_a_call_and_persists_result(make_item, monkeypatch):
    item = make_item(org="Acme", sector=config.SECTOR_UNKNOWN)
    items = [item]

    def fake_post(url, *, json, headers, timeout):
        # Régression du run réel 33139189464 : 4 000 tokens ont été presque
        # entièrement consommés par le raisonnement, sans aucun JSON visible.
        assert json["max_output_tokens"] >= 25_000
        organisations = json["input"][1]["content"]
        payload = {
            "organisations": [{
                "organisation_key": item.Organisation_Key,
                "sector": config.SECTOR_TECH,
                "confidence": 0.8,
                "basis": "explicit_activity",
                "reason": "L'activité éditoriale décrit un acteur technologique.",
            }],
        }
        return _Response(payload=_payload(payload))

    _enable_llm(monkeypatch, fake_post)
    report = osl.enrich_unknown_organisation_sectors(
        items, reference={}, source_fact_rows=[], org_cache_rows=[], cache_rows=[],
    )
    assert report.cache_misses == 1
    assert report.calls == 1
    assert report.candidates == 1
    row = next(r for r in report.cache_rows if r["Organisation_Key"] == item.Organisation_Key)
    assert row["Sector"] == config.SECTOR_TECH


def test_dry_run_never_calls_llm_or_writes(make_item, monkeypatch):
    item = make_item(org="Acme", sector=config.SECTOR_UNKNOWN)
    items = [item]
    called = {"count": 0}

    def fake_post(url, *, json, headers, timeout):
        called["count"] += 1
        return _Response(payload=_payload({"organisations": []}))

    _enable_llm(monkeypatch, fake_post)
    report = osl.enrich_unknown_organisation_sectors(
        items, reference={}, source_fact_rows=[], org_cache_rows=[], cache_rows=[], dry_run=True,
    )
    assert called["count"] == 0
    assert report.dry_run is True


# --------------------------------------------------------------------------
# Réponse JSON (§32)
# --------------------------------------------------------------------------


def test_response_parsing_is_resilient_to_bad_entries(monkeypatch):
    batch = [
        ("acme", _context("acme", "Acme")),
        ("orgb", _context("orgb", "Orga B")),
    ]

    def fake_post(url, *, json, headers, timeout):
        payload = {
            "organisations": [
                {"organisation_key": "acme", "sector": config.SECTOR_TECH, "confidence": 0.9, "basis": "explicit_activity", "reason": "r"},
                # Organisation inconnue dans la réponse : ignorée.
                {"organisation_key": "unknown-org", "sector": config.SECTOR_TECH, "confidence": 0.9, "basis": "explicit_activity", "reason": "r"},
                # Duplicat : la seconde entrée pour "acme" est ignorée.
                {"organisation_key": "acme", "sector": config.SECTOR_HEALTH, "confidence": 0.9, "basis": "explicit_activity", "reason": "r"},
                # Secteur hors taxonomie.
                {"organisation_key": "orgb", "sector": "Secteur Invalide", "confidence": 0.9, "basis": "explicit_activity", "reason": "r"},
            ],
        }
        return _Response(payload=_payload(payload))

    _enable_llm(monkeypatch, fake_post)
    result = osl.call_llm_batch(batch)
    assert set(result) == {"acme"}
    assert result["acme"].sector == config.SECTOR_TECH


def test_invalid_confidence_and_basis_are_rejected(monkeypatch):
    batch = [("acme", _context("acme", "Acme"))]

    def fake_post(url, *, json, headers, timeout):
        payload = {"organisations": [
            {"organisation_key": "acme", "sector": config.SECTOR_TECH, "confidence": 1.5, "basis": "name_semantics", "reason": "r"},
        ]}
        return _Response(payload=_payload(payload))

    _enable_llm(monkeypatch, fake_post)
    assert osl.call_llm_batch(batch) == {}

    def fake_post_bad_basis(url, *, json, headers, timeout):
        payload = {"organisations": [
            {"organisation_key": "acme", "sector": config.SECTOR_TECH, "confidence": 0.5, "basis": "made_up", "reason": "r"},
        ]}
        return _Response(payload=_payload(payload))

    monkeypatch.setattr(llm_runtime.requests, "post", fake_post_bad_basis)
    assert osl.call_llm_batch(batch) == {}


def test_name_semantics_and_low_confidence_are_not_publishable(monkeypatch):
    batch = [("acme", _context("acme", "Acme")), ("orgb", _context("orgb", "Orga B"))]

    def fake_post(url, *, json, headers, timeout):
        return _Response(payload=_payload({"organisations": [
            {"organisation_key": "acme", "sector": config.SECTOR_TECH, "confidence": 0.95, "basis": "name_semantics", "reason": "nom seul"},
            {"organisation_key": "orgb", "sector": config.SECTOR_HEALTH, "confidence": 0.60, "basis": "explicit_activity", "reason": "confiance faible"},
        ]}))

    _enable_llm(monkeypatch, fake_post)
    assert osl.call_llm_batch(batch) == {}


def test_charitable_activity_is_not_forced_into_business_or_agriculture(monkeypatch):
    context = osl.OrganisationContext(
        organisation_key="banque-alimentaire",
        organisation="Banque Alimentaire de Strasbourg",
        evidence_details=({"text": "association fournissant de l'aide alimentaire"},),
    )

    def fake_post(url, *, json, headers, timeout):
        return _Response(payload=_payload({"organisations": [{
            "organisation_key": "banque-alimentaire",
            "sector": osec.SECTOR_AGRICULTURE,
            "confidence": 0.90,
            "basis": "multiple_signals",
            "reason": "denrées alimentaires",
        }]}))

    _enable_llm(monkeypatch, fake_post)
    assert osl.call_llm_batch([("banque-alimentaire", context)]) == {}


def test_insufficient_basis_and_unknown_sector_are_treated_as_abstention(monkeypatch):
    batch = [("acme", _context("acme", "Acme"))]

    def fake_post(url, *, json, headers, timeout):
        payload = {"organisations": [
            {"organisation_key": "acme", "sector": config.SECTOR_UNKNOWN, "confidence": 0.9, "basis": "insufficient", "reason": "aucun signal"},
        ]}
        return _Response(payload=_payload(payload))

    _enable_llm(monkeypatch, fake_post)
    assert osl.call_llm_batch(batch) == {}


def test_invalid_json_is_non_blocking(monkeypatch):
    batch = [("acme", _context("acme", "Acme"))]

    def fake_post(url, *, json, headers, timeout):
        return _Response(payload={
            "status": "completed",
            "output": [{"type": "message", "content": [{"type": "output_text", "text": "not json"}]}],
            "usage": {},
        })

    _enable_llm(monkeypatch, fake_post)
    try:
        osl.call_llm_batch(batch)
        raised = False
    except llm_runtime.LlmError:
        raised = True
    assert raised, "une réponse non-JSON doit rester une LlmError gérée par l'appelant"


# --------------------------------------------------------------------------
# Résilience (§34)
# --------------------------------------------------------------------------


def test_missing_api_key_is_non_blocking(make_item, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(llm_runtime, "_RUNTIME", llm_runtime.LlmRuntime())
    item = make_item(org="Acme", sector=config.SECTOR_UNKNOWN)
    report = osl.enrich_unknown_organisation_sectors(
        [item], reference={}, source_fact_rows=[], org_cache_rows=[], cache_rows=[],
    )
    assert report.llm_available is False
    assert report.calls == 0
    assert item.Sector == config.SECTOR_UNKNOWN


def test_llm_error_on_one_batch_does_not_abort_enrichment(make_item, monkeypatch):
    first = make_item(org="Acme", sector=config.SECTOR_UNKNOWN)
    second = make_item(source_item_id="2", org="Orga B", sector=config.SECTOR_UNKNOWN, url="https://example.org/b")

    def fake_post(url, *, json, headers, timeout):
        return _Response(status_code=500, text="boom")

    _enable_llm(monkeypatch, fake_post)
    report = osl.enrich_unknown_organisation_sectors(
        [first, second], reference={}, source_fact_rows=[], org_cache_rows=[], cache_rows=[],
        batch_size=1,
    )
    # Deux lots, deux échecs réseau : aucun appel ne bloque l'autre, et la
    # fonction retourne normalement (pas d'exception propagée).
    assert report.candidates == 0
    assert first.Sector == config.SECTOR_UNKNOWN
    assert second.Sector == config.SECTOR_UNKNOWN


# --------------------------------------------------------------------------
# Politique de convergence (§20 à §23, §33)
# --------------------------------------------------------------------------


def _llm_evidence(key, organisation, sector, *, basis="name_semantics"):
    return osec.OrganisationSectorEvidence(
        key, organisation, sector, osec.EVIDENCE_LLM_ORGANISATION, "0.90",
        source="llm:gpt-5-nano", evidence_text=basis,
    )


def test_llm_only_is_confirmed_with_low_confidence():
    """Revirement de politique (audit 2026-08-26, décision explicite) :
    un candidat LLM organisationnel seul, sans corroboration, est
    désormais CONFIRMÉ et appliqué à Item.Sector (ancien
    STATUS_TENTATIVE, jamais appliqué, retiré) — seule la confiance LOW
    le distingue encore d'une preuve forte."""
    evidence = [_llm_evidence("acme", "Acme", config.SECTOR_TECH)]
    decision = osec.resolve_organisation_sector("acme", "Acme", evidence)
    assert decision.status == osec.STATUS_CONFIRMED
    assert decision.confidence == "LOW"
    assert decision.sector == config.SECTOR_TECH


def test_llm_plus_naf_concordant_confirms(make_item):
    naf_evidence = osec.OrganisationSectorEvidence(
        "acme", "Acme", config.SECTOR_HEALTH, osec.EVIDENCE_NAF_PRECISE, "HIGH",
        source="registre entreprise", evidence_text="Activity_Code=86.10Z",
    )
    llm_evidence = _llm_evidence("acme", "Acme", config.SECTOR_HEALTH)
    decision = osec.resolve_organisation_sector("acme", "Acme", [naf_evidence, llm_evidence])
    assert decision.status == osec.STATUS_CONFIRMED
    assert decision.sector == config.SECTOR_HEALTH


def test_llm_plus_official_subject_activity_concordant_confirms():
    official = osec.OrganisationSectorEvidence(
        "acme", "Acme Groupe", config.SECTOR_CONSTRUCTION, osec.EVIDENCE_OFFICIAL_SUBJECT_ACTIVITY, "HIGH",
    )
    llm_evidence = _llm_evidence("acme", "Acme Groupe", config.SECTOR_CONSTRUCTION)
    decision = osec.resolve_organisation_sector("acme", "Acme Groupe", [official, llm_evidence])
    assert decision.status == osec.STATUS_CONFIRMED
    assert decision.sector == config.SECTOR_CONSTRUCTION


def test_llm_plus_validated_org_concordant_confirms():
    validated = osec.OrganisationSectorEvidence(
        "acme", "Acme", config.SECTOR_ENERGY, osec.EVIDENCE_VALIDATED_ITEM, "HIGH",
    )
    llm_evidence = _llm_evidence("acme", "Acme", config.SECTOR_ENERGY)
    decision = osec.resolve_organisation_sector("acme", "Acme", [validated, llm_evidence])
    assert decision.status == osec.STATUS_CONFIRMED
    assert decision.sector == config.SECTOR_ENERGY


def test_llm_wins_when_official_subject_activity_disagrees():
    """Refonte 2026-08-26 ("preuves partout, décision unique à la fin") :
    official_subject_activity n'est plus dans PRECEDENCE (ni dans
    STRONG_EVIDENCE_TYPES) — ce n'est plus qu'un contexte parmi d'autres
    pour le LLM final. llm_organisation, seul type restant présent ici,
    tranche donc désormais seul (confidence LOW, jamais une preuve forte),
    et le secteur écarté reste journalisé pour audit."""
    weak_official = osec.OrganisationSectorEvidence(
        "acme", "Acme", config.SECTOR_HEALTH, osec.EVIDENCE_OFFICIAL_SUBJECT_ACTIVITY, "HIGH",
    )
    llm_evidence = _llm_evidence("acme", "Acme", config.SECTOR_TECH)
    decision = osec.resolve_organisation_sector("acme", "Acme", [weak_official, llm_evidence])
    assert osec.EVIDENCE_OFFICIAL_SUBJECT_ACTIVITY not in osec.PRECEDENCE
    assert decision.status == osec.STATUS_CONFIRMED
    assert decision.confidence == "LOW"
    assert decision.sector == config.SECTOR_TECH
    assert decision.winning_evidence_type == osec.EVIDENCE_LLM_ORGANISATION
    assert config.SECTOR_HEALTH in decision.conflicting_sectors


def test_llm_wins_when_source_activity_disagrees():
    """Refonte 2026-08-26 ("preuves partout, décision unique à la fin") :
    source_activity n'est plus dans PRECEDENCE — ce n'est plus qu'un
    contexte pour le LLM final, jamais un concurrent dans l'arbitrage.
    llm_organisation, seul type restant présent, tranche seul."""
    weak_registry_like = osec.OrganisationSectorEvidence(
        "acme", "Acme", config.SECTOR_RETAIL, osec.EVIDENCE_SOURCE_ACTIVITY, "MEDIUM",
    )
    llm_evidence = _llm_evidence("acme", "Acme", config.SECTOR_SERVICES)
    decision = osec.resolve_organisation_sector("acme", "Acme", [weak_registry_like, llm_evidence])
    assert osec.EVIDENCE_SOURCE_ACTIVITY not in osec.PRECEDENCE
    assert decision.status == osec.STATUS_CONFIRMED
    assert decision.confidence == "LOW"
    assert decision.sector == config.SECTOR_SERVICES
    assert decision.winning_evidence_type == osec.EVIDENCE_LLM_ORGANISATION
    assert config.SECTOR_RETAIL in decision.conflicting_sectors
