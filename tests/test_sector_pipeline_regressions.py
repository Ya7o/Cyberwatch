import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from cyberwatch import config, dedup, enrichment, sector_repair, sector_resolution, site, source_facts_ai as ai
from cyberwatch.model import Item, Incident
from cyberwatch.normalize import organisation_key
from cyberwatch.sector_activity import ACTIVITY_FIELDS
from cyberwatch.source_facts_ai_activity import normalize_activity


def test_site_blocks_lost_sector_before_writing(monkeypatch):
    from cyberwatch import store
    monkeypatch.setattr(store, 'load_items', lambda: [])
    monkeypatch.setattr(store, 'load_incidents', lambda: [])
    monkeypatch.setattr(store, 'load_source_facts', lambda: [])
    monkeypatch.setattr(store, 'load_sector_resolution', lambda: [])
    monkeypatch.setattr(site._legacy, '_source_facts_by_incident', lambda *_: {})
    monkeypatch.setattr(site._legacy, '_local_analysis_by_incident', lambda *_: {})
    monkeypatch.setattr(site._legacy, 'incidents_payload', lambda *_: [
        {'id': 'incident', 'sector': config.SECTOR_UNKNOWN}])
    monkeypatch.setattr(site, '_threat_decisions_by_incident', lambda *_: {})
    monkeypatch.setattr(site, '_resolved_details', lambda *_: {})
    monkeypatch.setattr(site, '_sector_decisions_by_incident', lambda *_: {
        'incident': [{'Resolved_Sector': config.SECTOR_RETAIL, 'Reason': 'ACTIVITY_RULE'}]})
    with pytest.raises(ValueError, match='sector_incident_projection_gap'):
        site.build()


def test_frozen_production_examples_repaired_without_identity_changes():
    fixture = json.loads((Path(__file__).parent / 'fixtures/sector_audit_2026-09-05.json').read_text())
    items = [Item.from_row(r) for r in fixture['items']]
    incidents = [Incident.from_row(r) for r in fixture['incidents']]
    references = enrichment.load_reference()
    rows, report = sector_repair.repair_snapshot(items, incidents, fixture['facts'], fixture['cache'], references, [])
    assert report['unknown_before'] == 5
    assert report['unknown_after'] == 0
    sectors = {organisation_key(i.Organisation): i.Secteur for i in incidents}
    assert sectors == {'preference formations': config.SECTOR_EDUCATION,
                       'zerogaspi': config.SECTOR_RETAIL, 'reso': config.SECTOR_RETAIL,
                       'cma occitanie': config.SECTOR_ADMIN,
                       'chambre de metiers et de l artisanat d occitanie': config.SECTOR_ADMIN}
    originals = {r['Incident_ID']: Incident.from_row(r).to_row() for r in fixture['incidents']}
    for incident in incidents:
        assert {k:v for k,v in incident.to_row().items() if k != 'Secteur'} == {
            k:v for k,v in originals[incident.Incident_ID].items() if k != 'Secteur'}
    repaired_facts = copy.deepcopy(fixture['facts'])
    second, again = sector_repair.repair_snapshot(items, incidents, fixture['facts'], fixture['cache'], references, rows)
    assert again['changes'] == []
    assert fixture['facts'] == repaired_facts
    fields = ('Resolved_Sector', 'Status', 'Reason', 'Confidence', 'Evidence', 'Evidence_URL')
    assert [[r[k] for k in fields] for r in rows] == [[r[k] for k in fields] for r in second]


def test_finalize_snapshot_transports_facts_and_preserves_provenance(monkeypatch):
    monkeypatch.setattr(enrichment, 'load_reference', lambda: {})
    item = Item(Item_ID='test', Organisation_Raw='Exemple', Organisation_Key='exemple',
                Sector='Inconnu', Source_ID='FRENCHBREACHES', Published_Date='2026-09-04')
    fact = {'Item_ID':'test', 'Activity_Description':'vente en ligne de chaussures',
            'Activity_Sector_Match':config.SECTOR_RETAIL,
            'Evidence_JSON':json.dumps({'Activity_Description':'Exemple commercialise en ligne des chaussures.'})}
    report = enrichment.finalize_snapshot([item], [fact], previous_sector_rows=[])
    assert report.items[0].Sector == report.incidents[0].Secteur == config.SECTOR_RETAIL
    assert sector_resolution.fact_transport_gaps([Item(**{**item.to_row(), 'Sector':'Inconnu'})], [fact], {}) == ['test']
    second = enrichment.finalize_snapshot(report.items, [fact], previous_sector_rows=report.sector_resolution_rows)
    assert second.sector_resolution_rows[0]['Status'] == 'inferred'


def test_old_default_never_becomes_confirmed():
    item = Item(Item_ID='opaque', Organisation_Raw='Opaque', Sector=config.SECTOR_SERVICES)
    previous = [{'Item_ID':'opaque', 'Resolved_Sector':config.SECTOR_SERVICES,
                 'Reason':'DEFAULT_OPERATIONAL_FALLBACK', 'Status':'inferred_low'}]
    rows = sector_resolution.resolve_items([item], [], {}, previous_rows=previous)
    assert rows[0]['Resolved_Sector'] == config.SECTOR_UNKNOWN
    assert rows[0]['Status'] == 'unknown'


@pytest.mark.parametrize('order', [(config.SECTOR_RETAIL, config.SECTOR_TECH), (config.SECTOR_TECH, config.SECTOR_RETAIL)])
def test_source_disagreement_is_order_independent(order):
    items = [Item(Organisation_Key='example', Organisation_Raw='Example', Published_Date='2026-09-04',
                  Source_ID=str(n), Item_ID=str(n), Sector=s) for n,s in enumerate(order)]
    assert dedup.build_incidents(items)[0].Secteur == config.SECTOR_UNKNOWN


def test_valid_source_cannot_hide_an_explicit_activity_conflict():
    first = Item(Organisation_Raw='Example', Sector=config.SECTOR_RETAIL)
    other = Item(Organisation_Raw='Example', Sector=config.SECTOR_UNKNOWN)
    other._sector_decision = sector_resolution.SectorDecision('Inconnu', 'unknown', 'ACTIVITY_SECTOR_CONFLICT', 0, 'conflict')
    assert sector_resolution.component_sector([first, other]) == config.SECTOR_UNKNOWN


def test_partial_literal_quote_can_bind_to_victim_in_same_sentence():
    context = 'ZeroGaspi commercialise en ligne des produits anti-gaspillage.'
    raw = {field: {'value': 'vente en ligne' if field=='activity_description' else config.SECTOR_RETAIL,
                    'evidence': 'commercialise en ligne des produits anti-gaspillage.', 'confidence': .9}
           for field in ACTIVITY_FIELDS}
    normalized, reasons = normalize_activity(raw, context, 'ZeroGaspi')
    assert set(normalized) == ACTIVITY_FIELDS
    assert normalized['activity_description']['evidence'] == context
    assert reasons == {}


@pytest.mark.parametrize('context', [
    'ZeroGaspi utilise son fournisseur Acme, éditeur de logiciels.',
    'Acme, fournisseur de ZeroGaspi, édite des logiciels.',
    'ZeroGaspi est victime. Acme commercialise en ligne des produits.',
])
def test_supplier_activity_is_not_promoted(context):
    raw = {field: {'value':config.SECTOR_TECH if field=='activity_sector_match' else 'éditeur de logiciels',
                    'evidence':context, 'confidence':.9} for field in ACTIVITY_FIELDS}
    normalized, _ = normalize_activity(raw, context, 'ZeroGaspi')
    assert 'activity_sector_match' not in normalized


def test_a_brand_name_is_not_activity_evidence():
    raw = {field: {'value':config.SECTOR_RETAIL if field=='activity_sector_match' else 'vente de jeux vidéo',
                    'evidence':'Micromania.', 'confidence':1} for field in ACTIVITY_FIELDS}
    assert normalize_activity(raw, 'Micromania.', 'Micromania')[0] == {}


def _activity_runtime():
    return SimpleNamespace(cache={'key':{'fields':{}}}, semantic_retries=0,
                           semantic_recovered_on_retry=0, semantic_first_misses=0,
                           semantic_new_abstentions=0)


def test_explicit_activity_absence_is_a_terminal_abstention():
    """Le modèle n'a rien proposé : décision terminale, pas une boucle de reprise."""
    runtime = _activity_runtime()
    ai._store_field_cache(runtime, 'key', None, None, ACTIVITY_FIELDS, {}, raw={}, reasons={})
    record = runtime.cache['key']['fields']['activity_description']
    assert record['status'] == 'abstained'
    assert record.get('semantic_attempts') is None
    assert runtime.semantic_new_abstentions == 2


def test_rejected_activity_proposal_keeps_a_second_attempt():
    """Une valeur proposée puis refusée consomme une tentative, pas les deux."""
    runtime = _activity_runtime()
    raw = {'activity_description': {'value': 'suivi des commandes', 'confidence': 0.9,
                                    'evidence': 'chez l un de ses prestataires'}}
    ai._store_field_cache(runtime, 'key', None, None, {'activity_description'}, {},
                          raw=raw, reasons={'activity_description': 'ACTIVITY_THIRD_PARTY'})
    record = runtime.cache['key']['fields']['activity_description']
    assert record['status'] == ai.CACHE_STATUS_REJECTED
    assert record['semantic_attempts'] == 1
    assert record['rejection_kind'] == 'THIRD_PARTY_ACTIVITY'

    ai._store_field_cache(runtime, 'key', None, None, {'activity_description'}, {},
                          raw=raw, reasons={'activity_description': 'ACTIVITY_THIRD_PARTY'})
    record = runtime.cache['key']['fields']['activity_description']
    assert record['status'] == ai.CACHE_STATUS_REJECTED_EXHAUSTED
    assert record['semantic_attempts'] == 2


def test_status_is_scoped_to_incident_not_another_event_of_same_company(monkeypatch):
    first = Item(Item_ID='one', Organisation_Key='example')
    second = Item(Item_ID='two', Organisation_Key='example')
    monkeypatch.setattr(site._legacy, '_components_with_stable_incident_ids', lambda items: [([first],'inc-one'),([second],'inc-two')])
    monkeypatch.setattr(site.store, 'load_sector_resolution', lambda: [
        {'Item_ID':'one','Resolved_Sector':config.SECTOR_RETAIL,'Status':'referenced','Reason':'REFERENCE_EXACT'},
        {'Item_ID':'two','Resolved_Sector':config.SECTOR_UNKNOWN,'Status':'unknown','Reason':'ACTIVITY_SECTOR_CONFLICT'}])
    decisions = site._sector_decisions_by_incident([first, second])
    assert site._sector_status({'id':'inc-two','org':'example','sector':'Inconnu'}, decisions)['reason'] == 'ACTIVITY_SECTOR_CONFLICT'
