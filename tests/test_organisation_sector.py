import random

import pytest

from cyberwatch import config, enrichment, organisation_sector as osec, store


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


def test_propagation_from_official_subject_activity(make_item):
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
    assert decision.status == osec.STATUS_CONFIRMED
    assert decision.sector == config.SECTOR_CONSTRUCTION


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


def test_tentative_from_classifiable_source_activity_alone(make_item):
    """Révision §9 Cas 4 (audit 2026-08-26, cas réels Klark.ai/TimeTonic/
    Groupe Bernard) : un indice métier explicite et classable — le
    classificateur strict le reconnaît, pas un simple mot-clé du récit —
    suffit désormais seul à afficher un secteur "supposé" (TENTATIVE)
    plutôt que rien, même sans candidat LLM convergent. Jamais Confirmé ni
    appliqué à Item.Sector pour autant : seule une véritable corroboration
    (preuve forte ou LLM convergent) permet cela."""
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

    assert decision.status == osec.STATUS_TENTATIVE
    assert decision.sector == config.SECTOR_TECH
    assert osec.EVIDENCE_SOURCE_ACTIVITY in decision.evidence_types

    changed, _provenance = osec.apply_organisation_sector_decisions([source, sibling], decisions)
    assert changed == 0
    assert source.Sector == config.SECTOR_UNKNOWN

    tentative = osec.tentative_provenance([source, sibling], decisions)
    assert {row["Item_ID"] for row in tentative} == {source.Item_ID, sibling.Item_ID}
    assert all(row["Candidate_Value"] == config.SECTOR_TECH for row in tentative)


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


def test_conflict_between_two_strong_evidences(make_item):
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
    assert decision.status == osec.STATUS_CONFLICT
    assert decision.sector == config.SECTOR_UNKNOWN
    assert set(decision.conflicting_sectors) == {config.SECTOR_CONSTRUCTION, config.SECTOR_TECH}

    changed, provenance = osec.apply_organisation_sector_decisions([item], decisions)
    assert changed == 0
    assert item.Sector == config.SECTOR_UNKNOWN


def test_multiple_identical_strong_evidences_confirm(make_item):
    first = make_item(org="Acme", sector=config.SECTOR_UNKNOWN)
    second = make_item(source_item_id="2", org="Acme", sector=config.SECTOR_UNKNOWN, url="https://example.org/b")
    reference = _reference(first.Organisation_Key, "Acme", config.SECTOR_SERVICES)
    org_cache_rows = [{
        "Organisation_Key": first.Organisation_Key,
        "Query_Name": "Acme",
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


def test_known_item_is_never_overwritten_by_weaker_evidence(make_item):
    item = make_item(org="Acme", sector=config.SECTOR_HEALTH)
    reference = _reference(item.Organisation_Key, "Acme", config.SECTOR_TECH)
    decisions = osec.resolve_all_organisation_sectors([item], reference=reference)
    changed, provenance = osec.apply_organisation_sector_decisions([item], decisions)
    assert changed == 0
    assert provenance == []
    assert item.Sector == config.SECTOR_HEALTH
