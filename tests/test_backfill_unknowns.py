from cyberwatch import config, enrichment


def test_backfill_threat_from_explicit_leak_phrases(make_item):
    titles = (
        "Données diffusées",
        "Données revendiquées",
        "Documents exposés",
        "Comptes en vente",
        "Dossiers mis en vente",
        "Les données de 12 800 agents diffusées sur le darkweb",
        "Les données revendiqués après une compromission",
        "Documents RH et pièces d’identité exposés",
        "La fuite serait bien plus importante que prévu",
    )
    for index, title in enumerate(titles):
        item = make_item(
            threat=config.THREAT_UNKNOWN,
            title=title,
            url=f"https://leak-{index}",
        )
        enrichment.backfill_unknowns([item], {})
        assert item.Threat == config.THREAT_LEAK


def test_backfill_never_overwrites_known_threat(make_item):
    item = make_item(
        threat=config.THREAT_RANSOMWARE,
        title="Données diffusées après un ransomware",
        url="https://known-threat",
    )
    enrichment.backfill_unknowns([item], {})
    assert item.Threat == config.THREAT_RANSOMWARE


def test_backfill_location_uses_title_and_organisation(make_item):
    paris = make_item(
        org="Organisation Paris",
        location=config.LOC_INCONNU,
        title="Incident à Paris",
        url="https://paris",
    )
    reunion = make_item(
        location=config.LOC_INCONNU,
        org="Association 974",
        title="Incident",
        url="https://reunion",
    )
    mayotte = make_item(
        location=config.LOC_INCONNU,
        org="Service Mayotte",
        title="Incident",
        url="https://mayotte",
    )
    enrichment.backfill_unknowns([paris, reunion, mayotte], {})
    assert paris.Location == config.LOC_FRANCE
    assert reunion.Location == config.LOC_REUNION
    assert mayotte.Location == config.LOC_MAYOTTE


def test_backfill_reuses_only_one_known_location(make_item):
    known = make_item(
        org="Organisation Alpha",
        location=config.LOC_FRANCE,
        url="https://known",
    )
    unknown = make_item(
        org="Organisation Alpha",
        location=config.LOC_INCONNU,
        url="https://unknown",
    )
    enrichment.backfill_unknowns([known, unknown], {})
    assert unknown.Location == config.LOC_FRANCE


def test_backfill_reuses_location_found_during_same_run(make_item):
    explicit = make_item(
        org="Organisation Beta",
        location=config.LOC_INCONNU,
        title="Incident à Paris",
        url="https://explicit",
    )
    unknown = make_item(
        org="Organisation Beta",
        location=config.LOC_INCONNU,
        title="Incident",
        url="https://unknown-beta",
    )
    enrichment.backfill_unknowns([explicit, unknown], {})
    assert explicit.Location == config.LOC_FRANCE
    assert unknown.Location == config.LOC_FRANCE


def test_backfill_keeps_conflicting_or_existing_location(make_item):
    france = make_item(
        org="Organisation",
        location=config.LOC_FRANCE,
        url="https://fr",
    )
    mayotte = make_item(
        org="Organisation",
        location=config.LOC_MAYOTTE,
        url="https://yt",
    )
    unknown = make_item(
        org="Organisation",
        location=config.LOC_INCONNU,
        url="https://unknown",
    )
    fixed = make_item(
        org="Organisation",
        location=config.LOC_REUNION,
        url="https://fixed",
    )
    enrichment.backfill_unknowns([france, mayotte, unknown, fixed], {})
    assert unknown.Location == config.LOC_INCONNU
    assert fixed.Location == config.LOC_REUNION
