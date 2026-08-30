import random

import pytest

from cyberwatch import config, enrichment, org_enrichment, organisation_sector as osec, store


@pytest.fixture(autouse=True)
def _isolate_data_dir(monkeypatch, tmp_path):
    """collect_organisation_evidence lit par défaut le cache LLM (P1) depuis
    un chemin dérivé de store.ITEMS_CSV : jamais data/ réel dans les tests."""
    monkeypatch.setattr(store, "ITEMS_CSV", tmp_path / "items.csv")


def _reference(key, organisation, sector, *, reason="validation humaine", url="https://acme.example/about"):
    return {
        key: enrichment.Enrichment(
            organisation=organisation, sector=sector, location="", scope="France",
            reason=reason, validation_url=url,
        )
    }


def test_propagation_from_manual_reference(make_item):
    source = make_item(org="Acme", sector=config.SECTOR_UNKNOWN)
    sibling = make_item(source_item_id="2", org="Acme", sector=config.SECTOR_UNKNOWN, url="https://example.org/b")
    reference = _reference(source.Organisation_Key, "Acme", config.SECTOR_SERVICES)

    decisions = osec.resolve_all_organisation_sectors([source, sibling], reference=reference)
    decision = decisions[source.Organisation_Key]
    assert decision.status == osec.STATUS_CONFIRMED
    assert decision.sector == config.SECTOR_SERVICES

    changed, provenance = osec.apply_organisation_sector_decisions([source, sibling], decisions)
    assert changed == 2
    assert source.Sector == config.SECTOR_SERVICES
    assert sibling.Sector == config.SECTOR_SERVICES
    assert all(row["Origin"] == osec.ORIGIN for row in provenance)


def test_propagation_from_naf_precise(make_item):
    source = make_item(org="Acme Sante", sector=config.SECTOR_UNKNOWN)
    sibling = make_item(source_item_id="2", org="Acme Sante", sector=config.SECTOR_UNKNOWN, url="https://example.org/b")
    org_cache_rows = [{
        "Organisation_Key": source.Organisation_Key,
        "Query_Name": "Acme Sante",
        "Match_Status": "MATCHED",
        "Company_ID": "123456789",
        "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
        "Activity_Code": "86.10Z",
    }]
    decisions = osec.resolve_all_organisation_sectors(
        [source, sibling], reference={}, org_cache_rows=org_cache_rows,
    )
    decision = decisions[source.Organisation_Key]
    assert decision.status == osec.STATUS_CONFIRMED
    assert decision.sector == config.SECTOR_HEALTH
    assert osec.EVIDENCE_NAF_PRECISE in decision.evidence_types

    changed, provenance = osec.apply_organisation_sector_decisions([source, sibling], decisions)
    assert changed == 2
    assert sibling.Sector == config.SECTOR_HEALTH


def test_naf_requires_a_current_validated_legal_identity(make_item):
    item = make_item(org="Acme Sante", sector=config.SECTOR_UNKNOWN)
    base = {
        "Organisation_Key": item.Organisation_Key,
        "Query_Name": "Acme Sante",
        "Company_ID": "123456789",
        "Activity_Code": "86.10Z",
        "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
    }
    for invalid in (
        {**base, "Match_Status": "AMBIGUOUS"},
        {**base, "Match_Status": "MATCHED", "Company_ID": ""},
        {**base, "Match_Status": "MATCHED", "Cache_Version": "old"},
    ):
        decisions = osec.resolve_all_organisation_sectors(
            [item], reference={}, org_cache_rows=[invalid], llm_cache_rows=[],
        )
        assert decisions[item.Organisation_Key].status == osec.STATUS_UNKNOWN


def test_evidence_audit_has_an_outcome_for_every_stage(make_item):
    item = make_item(org="Acme", sector=config.SECTOR_UNKNOWN)
    evidence = osec.collect_organisation_evidence(
        [item], reference={}, source_fact_rows=[{
            "Item_ID": item.Item_ID,
            "Source_ID": item.Source_ID,
            "Activity_Description": "Acme développe une plateforme SaaS.",
            "Activity_Sector_Match": config.SECTOR_TECH,
        }], org_cache_rows=[], llm_cache_rows=[], domain_page_rows=[],
    )
    rows = osec.evidence_audit_rows([item], evidence)
    assert {row["Evidence_Type"] for row in rows} == set(osec.AUDITED_EVIDENCE_TYPES)
    assert all(row["Outcome"] in {"PRODUCED", "NO_MATCH", "NOT_APPLICABLE"} for row in rows)
    assert any(
        row["Evidence_Type"] == osec.EVIDENCE_SOURCE_ACTIVITY
        and row["Outcome"] == "PRODUCED"
        for row in rows
    )


def test_official_subject_activity_alone_no_longer_confirms(make_item):
    """Refonte 2026-08-26 ("preuves partout, décision unique à la fin") :
    official_subject_activity n'est plus dans PRECEDENCE — comme tous les
    types faibles, il alimente uniquement le contexte du LLM organisationnel
    final (organisation_sector_llm.py, appel obligatoire dans qualify()),
    jamais une décision directe à lui seul."""
    source = make_item(org="Acme Groupe", sector=config.SECTOR_UNKNOWN)
    sibling = make_item(source_item_id="2", org="Acme Groupe", sector=config.SECTOR_UNKNOWN, url="https://example.org/b")
    org_cache_rows = [{
        "Organisation_Key": source.Organisation_Key,
        "Query_Name": "Acme Groupe",
        "Match_Status": "MATCHED",
        "Validated_Via": "official_subject_activity",
        "Validated_Sector": config.SECTOR_CONSTRUCTION,
        "Activity_Label": "Acme Groupe, leader europeen du BTP et des concessions, developpe les territoires.",
    }]
    decisions = osec.resolve_all_organisation_sectors(
        [source, sibling], reference={}, org_cache_rows=org_cache_rows,
    )
    decision = decisions[source.Organisation_Key]
    assert osec.EVIDENCE_OFFICIAL_SUBJECT_ACTIVITY not in osec.PRECEDENCE
    assert decision.status == osec.STATUS_UNKNOWN


def test_no_propagation_from_weak_source_activity_alone(make_item):
    source = make_item(org="Acme", sector=config.SECTOR_UNKNOWN)
    sibling = make_item(source_item_id="2", org="Acme", sector=config.SECTOR_UNKNOWN, url="https://example.org/b")
    source_fact_rows = [{
        "Item_ID": source.Item_ID,
        "Activity_Description": "Cinema municipal proposant des projections publiques.",
    }]
    decisions = osec.resolve_all_organisation_sectors(
        [source, sibling], reference={}, source_fact_rows=source_fact_rows,
    )
    decision = decisions[source.Organisation_Key]
    # §9 Cas 4 : un texte que le classificateur strict ne reconnaît pas
    # (aucun motif métier sûr) ne produit aucune preuve du tout, donc reste
    # Inconnu. Cas différent de test_tentative_from_classifiable_source_activity_alone
    # ci-dessous, où le texte EST reconnu par le classificateur.
    assert decision.status == osec.STATUS_UNKNOWN
    changed, provenance = osec.apply_organisation_sector_decisions([source, sibling], decisions)
    assert changed == 0
    assert provenance == []


def test_classifiable_source_activity_alone_is_only_context_now(make_item):
    """Révision §9 Cas 4 (audit 2026-08-26, cas réels Klark.ai/TimeTonic/
    Groupe Bernard), puis refonte du 2026-08-26 ("preuves partout, décision
    unique à la fin") : source_activity n'est plus dans PRECEDENCE — il
    n'alimente désormais que le contexte transmis au LLM organisationnel
    final, jamais une décision directe, même pour un indice métier
    explicite et classable. L'organisation reste UNKNOWN tant que le LLM
    final (organisation_sector_llm.py, appel obligatoire de qualify()) n'a
    pas tranché à partir de ce même contexte."""
    source = make_item(org="Acme", sector=config.SECTOR_UNKNOWN)
    sibling = make_item(source_item_id="2", org="Acme", sector=config.SECTOR_UNKNOWN, url="https://example.org/b")
    source_fact_rows = [{
        "Item_ID": source.Item_ID,
        "Activity_Description": "Acme développe une plateforme d'intelligence artificielle pour la relation client.",
    }]
    decisions = osec.resolve_all_organisation_sectors(
        [source, sibling], reference={}, source_fact_rows=source_fact_rows,
    )
    decision = decisions[source.Organisation_Key]

    assert osec.EVIDENCE_SOURCE_ACTIVITY not in osec.PRECEDENCE
    assert decision.status == osec.STATUS_UNKNOWN
    assert osec.EVIDENCE_SOURCE_ACTIVITY in decision.evidence_types

    changed, _provenance = osec.apply_organisation_sector_decisions([source, sibling], decisions)
    assert changed == 0
    assert source.Sector == config.SECTOR_UNKNOWN
    assert sibling.Sector == config.SECTOR_UNKNOWN


def test_no_propagation_from_org_sector_registry_origin(make_item):
    """La provenance ORG_SECTOR_REGISTRY (ancien resolver) n'est jamais réutilisée
    comme preuve forte : elle est explicitement exclue de la liste blanche §5."""
    source = make_item(org="Acme", sector=config.SECTOR_RETAIL)
    sibling = make_item(source_item_id="2", org="Acme", sector=config.SECTOR_UNKNOWN, url="https://example.org/b")
    previous_provenance = [{
        "Item_ID": source.Item_ID, "Field": "Sector", "Decision": "APPLIED",
        "Origin": "ORG_SECTOR_REGISTRY", "Final_Value": config.SECTOR_RETAIL,
        "Previous_Value": config.SECTOR_UNKNOWN,
    }]
    decisions = osec.resolve_all_organisation_sectors(
        [source, sibling], reference={}, previous_provenance=previous_provenance,
    )
    decision = decisions[source.Organisation_Key]
    assert decision.status == osec.STATUS_UNKNOWN
    assert osec.EVIDENCE_VALIDATED_ITEM not in decision.evidence_types


def test_no_self_validation_circularity(make_item):
    """Une décision appliquée par ce module elle-même ne redevient jamais
    une preuve au tour suivant (Origin=ORGANISATION_SECTOR_P0 exclu)."""
    source = make_item(org="Acme", sector=config.SECTOR_RETAIL)
    sibling = make_item(source_item_id="2", org="Acme", sector=config.SECTOR_UNKNOWN, url="https://example.org/b")
    previous_provenance = [{
        "Item_ID": sibling.Item_ID, "Field": "Sector", "Decision": "APPLIED",
        "Origin": osec.ORIGIN, "Final_Value": config.SECTOR_RETAIL,
        "Previous_Value": config.SECTOR_UNKNOWN,
    }]
    # sibling.Sector est encore Inconnu ici (fixture) : on simule le cas réel
    # où restore_organisation_sector_applications n'a pas encore tourné.
    sibling.Sector = config.SECTOR_RETAIL
    restored = osec.restore_organisation_sector_applications([source, sibling], previous_provenance)
    assert restored == 1
    assert sibling.Sector == config.SECTOR_UNKNOWN

    evidence = osec.collect_organisation_evidence(
        [source, sibling], reference={}, previous_provenance=previous_provenance,
    )
    # sibling ne doit produire aucune preuve validated_item pour un tiers.
    types = {e.evidence_type for e in evidence.get(source.Organisation_Key, [])}
    assert osec.EVIDENCE_VALIDATED_ITEM not in types


def test_manual_reference_outranks_official_subject_activity_no_longer_conflicts(make_item):
    """Révision de l'arbitrage (audit 2026-08-26) : un désaccord entre deux
    TYPES de preuve différents n'est plus un CONFLICT non résolu — la
    préséance tranche toujours (manual_reference > official_subject_activity
    ici). Le secteur perdant reste journalisé dans conflicting_sectors pour
    l'auditabilité, sans jamais l'emporter. Seule une contradiction interne
    au type le plus prioritaire présent reste un CONFLICT
    (cf. test_same_type_internal_disagreement_still_conflicts)."""
    item = make_item(org="Acme Groupe", sector=config.SECTOR_UNKNOWN)
    org_cache_rows = [
        {
            "Organisation_Key": item.Organisation_Key,
            "Query_Name": "Acme Groupe",
            "Match_Status": "MATCHED",
            "Validated_Via": "official_subject_activity",
            "Validated_Sector": config.SECTOR_CONSTRUCTION,
            "Activity_Label": "Acme Groupe, leader europeen du BTP et des concessions, developpe les territoires.",
        },
    ]
    reference = _reference(item.Organisation_Key, "Acme Groupe", config.SECTOR_TECH)
    decisions = osec.resolve_all_organisation_sectors(
        [item], reference=reference, org_cache_rows=org_cache_rows,
    )
    decision = decisions[item.Organisation_Key]
    assert decision.status == osec.STATUS_CONFIRMED
    assert decision.sector == config.SECTOR_TECH
    assert decision.winning_evidence_type == osec.EVIDENCE_MANUAL_REFERENCE
    assert config.SECTOR_CONSTRUCTION in decision.conflicting_sectors

    changed, provenance = osec.apply_organisation_sector_decisions([item], decisions)
    assert changed == 1
    assert item.Sector == config.SECTOR_TECH


def test_same_type_internal_disagreement_still_conflicts(make_item):
    """Deux preuves du MÊME type le plus prioritaire présent qui se
    contredisent restent un CONFLICT : ce n'est pas un désaccord entre deux
    sources indépendantes que la préséance peut trancher, mais une donnée
    incohérente avec elle-même à la source la plus fiable."""
    item = make_item(org="Acme", sector=config.SECTOR_UNKNOWN)
    evidence_a = osec.OrganisationSectorEvidence(
        item.Organisation_Key, "Acme", config.SECTOR_TECH, osec.EVIDENCE_MANUAL_REFERENCE, "HIGH",
    )
    evidence_b = osec.OrganisationSectorEvidence(
        item.Organisation_Key, "Acme", config.SECTOR_HEALTH, osec.EVIDENCE_MANUAL_REFERENCE, "HIGH",
    )
    decision = osec.resolve_organisation_sector(item.Organisation_Key, "Acme", [evidence_a, evidence_b])
    assert decision.status == osec.STATUS_CONFLICT
    assert decision.sector == config.SECTOR_UNKNOWN
    assert set(decision.conflicting_sectors) == {config.SECTOR_TECH, config.SECTOR_HEALTH}
    assert decision.winning_evidence_type == osec.EVIDENCE_MANUAL_REFERENCE


def test_cross_type_disagreement_precedence_winner(make_item):
    """naf_precise_v2 est plus prioritaire qu'official_subject_activity :
    en cas de désaccord, il gagne et l'autre reste en conflicting_sectors."""
    item = make_item(org="Acme", sector=config.SECTOR_UNKNOWN)
    naf_evidence = osec.OrganisationSectorEvidence(
        item.Organisation_Key, "Acme", config.SECTOR_HEALTH, osec.EVIDENCE_NAF_PRECISE, "HIGH",
    )
    official_evidence = osec.OrganisationSectorEvidence(
        item.Organisation_Key, "Acme", config.SECTOR_CONSTRUCTION, osec.EVIDENCE_OFFICIAL_SUBJECT_ACTIVITY, "HIGH",
    )
    decision = osec.resolve_organisation_sector(item.Organisation_Key, "Acme", [naf_evidence, official_evidence])
    assert decision.status == osec.STATUS_CONFIRMED
    assert decision.sector == config.SECTOR_HEALTH
    assert decision.winning_evidence_type == osec.EVIDENCE_NAF_PRECISE
    assert config.SECTOR_CONSTRUCTION in decision.conflicting_sectors


def test_single_llm_evidence_alone_is_confirmed_and_applied(make_item):
    """Généralisation de '1 indice minimum suffit' (revirement de politique,
    audit 2026-08-26) : même le type le moins prioritaire
    (llm_organisation), seul, suffit désormais à CONFIRMER et appliquer un
    secteur — ce n'est plus un cas spécial câblé en dur pour
    source_activity uniquement, et ce n'est plus seulement journalisé
    (ancien STATUS_TENTATIVE, retiré)."""
    item = make_item(org="Acme", sector=config.SECTOR_UNKNOWN)
    llm_evidence = osec.OrganisationSectorEvidence(
        item.Organisation_Key, "Acme", config.SECTOR_TECH, osec.EVIDENCE_LLM_ORGANISATION, "0.80",
    )
    decision = osec.resolve_organisation_sector(item.Organisation_Key, "Acme", [llm_evidence])
    assert decision.status == osec.STATUS_CONFIRMED
    assert decision.confidence == "LOW"
    assert decision.sector == config.SECTOR_TECH
    assert decision.winning_evidence_type == osec.EVIDENCE_LLM_ORGANISATION

    changed, _provenance = osec.apply_organisation_sector_decisions([item], {item.Organisation_Key: decision})
    assert changed == 1
    assert item.Sector == config.SECTOR_TECH


def test_multiple_identical_strong_evidences_confirm(make_item):
    first = make_item(org="Acme", sector=config.SECTOR_UNKNOWN)
    second = make_item(source_item_id="2", org="Acme", sector=config.SECTOR_UNKNOWN, url="https://example.org/b")
    reference = _reference(first.Organisation_Key, "Acme", config.SECTOR_SERVICES)
    org_cache_rows = [{
        "Organisation_Key": first.Organisation_Key,
        "Query_Name": "Acme",
        "Match_Status": "MATCHED",
        "Company_ID": "123456789",
        "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
        "Activity_Code": "70.22Z",
    }]
    decisions = osec.resolve_all_organisation_sectors(
        [first, second], reference=reference, org_cache_rows=org_cache_rows,
    )
    decision = decisions[first.Organisation_Key]
    assert decision.status == osec.STATUS_CONFIRMED
    assert decision.sector == config.SECTOR_SERVICES


def test_order_of_items_does_not_change_result(make_item):
    source = make_item(org="Acme", sector=config.SECTOR_UNKNOWN)
    sibling = make_item(source_item_id="2", org="Acme", sector=config.SECTOR_UNKNOWN, url="https://example.org/b")
    third = make_item(source_item_id="3", org="Acme", sector=config.SECTOR_UNKNOWN, url="https://example.org/c")
    reference = _reference(source.Organisation_Key, "Acme", config.SECTOR_SERVICES)
    items = [source, sibling, third]

    decisions_a = osec.resolve_all_organisation_sectors(items, reference=reference)
    shuffled = list(items)
    random.Random(1234).shuffle(shuffled)
    decisions_b = osec.resolve_all_organisation_sectors(shuffled, reference=reference)

    key = source.Organisation_Key
    assert decisions_a[key].status == decisions_b[key].status
    assert decisions_a[key].sector == decisions_b[key].sector
    assert decisions_a[key].evidence == decisions_b[key].evidence


def test_second_replay_is_idempotent(make_item):
    source = make_item(org="Acme", sector=config.SECTOR_UNKNOWN)
    sibling = make_item(source_item_id="2", org="Acme", sector=config.SECTOR_UNKNOWN, url="https://example.org/b")
    reference = _reference(source.Organisation_Key, "Acme", config.SECTOR_SERVICES)
    items = [source, sibling]

    decisions = osec.resolve_all_organisation_sectors(items, reference=reference)
    _changed, provenance = osec.apply_organisation_sector_decisions(items, decisions)

    restored = osec.restore_organisation_sector_applications(items, provenance)
    assert restored == 2
    assert sibling.Sector == config.SECTOR_UNKNOWN

    decisions_again = osec.resolve_all_organisation_sectors(items, reference=reference)
    _changed_again, provenance_again = osec.apply_organisation_sector_decisions(items, decisions_again)
    assert provenance_again == provenance
    assert sibling.Sector == config.SECTOR_SERVICES


def test_manual_authority_overwrites_known_item(make_item):
    item = make_item(org="Acme", sector=config.SECTOR_HEALTH)
    reference = _reference(item.Organisation_Key, "Acme", config.SECTOR_TECH)
    decisions = osec.resolve_all_organisation_sectors([item], reference=reference)
    changed, provenance = osec.apply_organisation_sector_decisions([item], decisions)
    assert changed == 1
    assert provenance[0]["Previous_Value"] == config.SECTOR_HEALTH
    assert item.Sector == config.SECTOR_TECH
