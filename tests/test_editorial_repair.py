"""Regression contracts from the September 6 source/sector audit."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from cyberwatch import config, dedup, duplicate_audit, sector, sector_activity, sector_resolution
from cyberwatch.collectors import feed
from cyberwatch.collectors.base import RawEntry


def test_html_comment_cannot_consume_editorial_body():
    html = ('<!-- override des <style> embarqués -->'
            '<main><article><p>Les Curistes est spécialisée dans les cures thermales.</p>'
            '</article></main><script>safe()</script>')
    text = feed.stable_frenchbreaches_detail_text(html)
    assert 'cures thermales' in text
    assert 'safe()' not in text and 'embarqués' not in text


def test_body_excludes_related_articles_and_keeps_paragraphs():
    html = ('<main><header>Navigation</header><article class="article-content">'
            '<h2>Qui est la victime ?</h2><p>Acme vend du mobilier.</p>'
            '<div><p>Deuxième paragraphe.</p></div></article>'
            '<article class="related-reading-card">Une autre victime</article></main>')
    text = feed.stable_frenchbreaches_detail_text(html)
    assert 'Acme vend du mobilier.' in text and '\n' in text
    assert 'Navigation' not in text and 'autre victime' not in text


def test_title_only_is_not_a_successful_hydration():
    entry = RawEntry(title='Acme', url='https://example.org/acme', published='2026-09-06')
    client = SimpleNamespace(fetch=lambda *_: SimpleNamespace(ok=True, text='<h1>Acme</h1>'))
    assert feed._hydrate_frenchbreaches_details(client, [entry], SimpleNamespace(exhausted=False)) == (1, 0)
    assert entry.source_metadata['detail_hydration']['status'] == 'CONTENT_INCOMPLETE'


def test_hydration_replaces_a_territory_title_with_explicit_victim():
    entry = RawEntry(title='Aveyron', url='https://example.org/aveyron', published='2026-09-06')
    html = ('<article class="article-content"><h1>Aveyron</h1>'
            '<p>Une importante fuite de données touche OnRecrute.enAveyron.fr, '
            'la plateforme dédiée à l’emploi du Département de l’Aveyron.</p></article>')
    client = SimpleNamespace(fetch=lambda *_: SimpleNamespace(ok=True, text=html))
    assert feed._hydrate_frenchbreaches_details(client, [entry], SimpleNamespace(exhausted=False)) == (1, 1)
    assert entry.organisation == 'OnRecrute.enAveyron.fr'
    activity, _ = sector_activity.activity_from_text(entry.organisation, entry.content)
    assert sector.classify_sector_activity(activity) == config.SECTOR_ADMIN


@pytest.mark.parametrize('org,text,expected', [
    ('Accent Rouge', 'Accent Rouge commercialise du mobilier, des luminaires et des portes.', config.SECTOR_RETAIL),
    ('Jouvet SAS', 'Jouvet SAS intervient dans la plomberie, le chauffage et la climatisation.', config.SECTOR_CONSTRUCTION),
    ('Répar’stores', 'Répar’stores est spécialisé dans la réparation et la modernisation de volets roulants.', config.SECTOR_CONSTRUCTION),
    ("Répar'Store", 'Répar’stores est spécialisé dans la réparation et la modernisation de volets roulants.', config.SECTOR_CONSTRUCTION),
    ('PassPass', 'Une fuite de données attribuée à Pass Pass, service de mobilité des Hauts-de-France, est revendiquée.', config.SECTOR_TRANSPORT),
    ('YouFid', 'YouFid est une plateforme de gestion de programmes de fidélité.', config.SECTOR_TECH),
    ('Les Curistes', 'Les Curistes est une plateforme spécialisée dans les cures thermales.', config.SECTOR_HOSPITALITY),
    ('OnRecrute.enAveyron.fr', 'OnRecrute.enAveyron.fr, la plateforme dédiée à l’emploi du Département de l’Aveyron, est concernée.', config.SECTOR_ADMIN),
])
def test_proven_activity_is_extracted_and_classified(org, text, expected):
    activity, proof = sector_activity.activity_from_text(org, text)
    assert activity and proof
    assert sector.classify_sector_activity(activity) == expected


def test_nonstandard_incident_prefix_still_binds_victim():
    text = 'Une importante fuite de données attribuée à Les Curistes, plateforme spécialisée dans les cures thermales, est revendiquée.'
    assert sector_activity.activity_from_text('Les Curistes', text)[0]


def test_specific_body_activity_wins_over_teaser():
    teaser = 'Accent Rouge, entreprise spécialisée dans l’aménagement intérieur haut de gamme, est touchée.'
    body = 'Accent Rouge commercialise du mobilier et des luminaires.'
    assert sector_activity.activity_from_text('Accent Rouge', teaser, body)[0] == body


@pytest.mark.parametrize('text', [
    'Le prestataire de Acme est spécialisé dans le chauffage.',
    'Acme utilise le logiciel de son fournisseur spécialisé dans le chauffage.',
    'Acme est client de Beta, une entreprise de plomberie.',
    'Acme Sud commercialise du mobilier.',
])
def test_third_party_and_homonym_do_not_supply_activity(text):
    assert sector_activity.activity_from_text('Acme', text) == ('', '')


def test_raw_sector_is_arbitrated_against_business_activity(make_item):
    item = make_item(org='Jouvet SAS', sector=config.SECTOR_UNKNOWN)
    proof = 'Jouvet SAS intervient dans la plomberie et le chauffage.'
    fact = {'Source_Sector_Raw': 'Manufacturing', 'Activity_Description': proof,
            'Evidence_JSON': json.dumps({'Activity_Description': proof})}
    result = sector_resolution.resolve_item(item, fact, {})
    assert result.sector == config.SECTOR_CONSTRUCTION
    assert result.reason == 'ACTIVITY_OVERRIDES_SOURCE_LABEL'
    assert 'Manufacturing' in result.evidence


def test_soft_time_gap_can_be_reviewed_but_not_merged_without_evidence(make_item):
    a = make_item(org='Acme', source='CYBERATTAQUE_ORG', published='2026-09-01')
    b = make_item(org='Acme', source='FRENCHBREACHES', published='2026-09-05')
    assert dedup.decide_merge(a, b).action == dedup.KEEP_SEPARATE
    assert len(duplicate_audit.find_daily_llm_candidates([b], [a, b])) == 1
