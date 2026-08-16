from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"bloc test attendu introuvable dans {path}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "tests/test_location_resolution.py",
    '_live_item("BONJOURLAFUITE", "Société Mayotte Test")',
    '_live_item("BONJOURLAFUITE", "Société Archipel Test")',
)

replace_once(
    "tests/test_location_and_veille_priority.py",
    "from cyberwatch import config, sources\n",
    "from cyberwatch import ai, config, org_enrichment, sources\n",
)

replace_once(
    "tests/test_location_and_veille_priority.py",
    '''@pytest.mark.parametrize("source_id", ["FRENCHBREACHES", "BONJOURLAFUITE"])
def test_french_leak_sources_default_to_france(source_id):
    spec = sources.by_id(source_id)
    assert spec is not None
    assert spec.location_rule == config.LOC_FRANCE

    item = entry_to_item(
        RawEntry(
            title="Organisation Exemple",
            published="2026-08-15",
            summary="Fuite de données confirmée.",
            url=f"https://example.test/{source_id.lower()}",
        ),
        spec,
        "2026-08-15T16:30:00+04:00",
        known_orgs={},
        entity_index={},
        territories={},
        reference={},
    )

    assert item is not None
    assert item.Location == config.LOC_FRANCE
''',
    '''@pytest.mark.parametrize("source_id", ["FRENCHBREACHES", "BONJOURLAFUITE"])
def test_french_leak_sources_default_to_france(source_id):
    spec = sources.by_id(source_id)
    assert spec is not None
    assert spec.location_rule == config.LOC_FRANCE

    entry = RawEntry(
        title="Organisation Exemple",
        published="2026-08-15",
        summary="Fuite de données confirmée.",
        url=f"https://example.test/{source_id.lower()}",
    )
    item = entry_to_item(
        entry,
        spec,
        "2026-08-15T16:30:00+04:00",
        known_orgs={},
        entity_index={},
        territories={},
        reference={},
    )

    assert item is not None
    # Le défaut source est volontairement différé pour laisser une chance à
    # l'enrichissement entreprise de fournir 974/976 en priorité.
    assert item.Location == config.LOC_INCONNU
    state = ai.AiRunState(
        enabled=False,
        org_enrichment=org_enrichment.OrgEnrichmentState(enabled=False),
    )
    ai.qualify_item(item, entry, spec, state)
    assert item.Location == config.LOC_FRANCE
''',
)

replace_once(
    "tests/test_runner.py",
    '''        assert item.Sector == config.SECTOR_ADMIN
        assert item.Location == config.LOC_REUNION
        assert item.Item_ID.startswith("ITM-")
''',
    '''        assert item.Sector == config.SECTOR_ADMIN
        # `entry_to_item` conserve désormais le défaut source pour l'étape
        # suivante du pipeline afin que l'enrichissement entreprise reste prioritaire.
        assert item.Location == config.LOC_INCONNU
        assert item.Item_ID.startswith("ITM-")
''',
)
