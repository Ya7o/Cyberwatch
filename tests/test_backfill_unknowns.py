from cyberwatch import config, enrichment


def test_backfill_threat_from_explicit_leak_phrases(make_item):
    for title in ("Données diffusées", "Données revendiquées", "Documents exposés", "Comptes en vente", "Dossiers mis en vente"):
        item = make_item(threat=config.THREAT_UNKNOWN, title=title, url=f"https://{title}")
        enrichment.backfill_unknowns([item], {})
        assert item.Threat == config.THREAT_LEAK


def test_backfill_location_uses_title_and_organisation(make_item):
    paris = make_item(org="Organisation Paris", location=config.LOC_INCONNU, title="Incident à Paris", url="https://paris")
    reunion = make_item(location=config.LOC_INCONNU, org="Association 974", title="Incident", url="https://reunion")
    mayotte = make_item(location=config.LOC_INCONNU, org="Service Mayotte", title="Incident", url="https://mayotte")
    enrichment.backfill_unknowns([paris, reunion, mayotte], {})
    assert paris.Location == config.LOC_FRANCE
    assert reunion.Location == config.LOC_REUNION
    assert mayotte.Location == config.LOC_MAYOTTE


def test_backfill_reuses_only_one_known_location(make_item):
    known = make_item(org="Organisation France", location=config.LOC_FRANCE, url="https://known")
    unknown = make_item(org="Organisation France", location=config.LOC_INCONNU, url="https://unknown")
    enrichment.backfill_unknowns([known, unknown], {})
    assert unknown.Location == config.LOC_FRANCE


def test_backfill_keeps_conflicting_or_existing_location(make_item):
    france = make_item(org="Organisation", location=config.LOC_FRANCE, url="https://fr")
    mayotte = make_item(org="Organisation", location=config.LOC_MAYOTTE, url="https://yt")
    unknown = make_item(org="Organisation", location=config.LOC_INCONNU, url="https://unknown")
    fixed = make_item(org="Organisation", location=config.LOC_REUNION, url="https://fixed")
    enrichment.backfill_unknowns([france, mayotte, unknown, fixed], {})
    assert unknown.Location == config.LOC_INCONNU
    assert fixed.Location == config.LOC_REUNION
