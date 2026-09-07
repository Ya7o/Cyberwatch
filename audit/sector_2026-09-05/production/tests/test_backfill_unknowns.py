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


def test_backfill_location_uses_only_safe_text_hints(make_item):
    paris = make_item(
        source="CYBERATTAQUE_ORG",
        org="Organisation Paris",
        location=config.LOC_INCONNU,
        title="Incident à Paris",
        url="https://paris",
    )
    reunion = make_item(
        source="CYBERATTAQUE_ORG",
        location=config.LOC_INCONNU,
        org="Association du département 974",
        title="Incident",
        url="https://reunion",
    )
    mayotte = make_item(
        source="CYBERATTAQUE_ORG",
        location=config.LOC_INCONNU,
        org="Service Mayotte",
        title="Incident",
        url="https://mayotte",
    )
    enrichment.backfill_unknowns([paris, reunion, mayotte], {})
    assert paris.Location == config.LOC_INCONNU
    assert reunion.Location == config.LOC_REUNION
    assert mayotte.Location == config.LOC_MAYOTTE


def test_backfill_does_not_reuse_one_known_location(make_item):
    known = make_item(
        source="CYBERATTAQUE_ORG",
        org="Organisation Alpha Sans Cache",
        location=config.LOC_FRANCE,
        url="https://known",
    )
    unknown = make_item(
        source="CYBERATTAQUE_ORG",
        org="Organisation Alpha Sans Cache",
        location=config.LOC_INCONNU,
        url="https://unknown",
    )
    enrichment.backfill_unknowns([known, unknown], {})
    assert unknown.Location == config.LOC_INCONNU


def test_backfill_does_not_propagate_location_found_during_same_run(make_item):
    explicit = make_item(
        source="CYBERATTAQUE_ORG",
        org="Organisation Beta Sans Cache",
        location=config.LOC_INCONNU,
        title="Entreprise réunionnaise victime d'un incident",
        url="https://explicit",
    )
    unknown = make_item(
        source="CYBERATTAQUE_ORG",
        org="Organisation Beta Sans Cache",
        location=config.LOC_INCONNU,
        title="Incident",
        url="https://unknown-beta",
    )
    enrichment.backfill_unknowns([explicit, unknown], {})
    assert explicit.Location == config.LOC_REUNION
    assert unknown.Location == config.LOC_INCONNU


def test_backfill_keeps_conflicting_or_existing_location(make_item):
    france = make_item(
        source="CYBERATTAQUE_ORG",
        org="Organisation Conflit Sans Cache",
        location=config.LOC_FRANCE,
        url="https://fr",
    )
    mayotte = make_item(
        source="CYBERATTAQUE_ORG",
        org="Organisation Conflit Sans Cache",
        location=config.LOC_MAYOTTE,
        url="https://yt",
    )
    unknown = make_item(
        source="CYBERATTAQUE_ORG",
        org="Organisation Conflit Sans Cache",
        location=config.LOC_INCONNU,
        url="https://unknown",
    )
    fixed = make_item(
        source="CYBERATTAQUE_ORG",
        org="Organisation Conflit Sans Cache",
        location=config.LOC_REUNION,
        url="https://fixed",
    )
    enrichment.backfill_unknowns([france, mayotte, unknown, fixed], {})
    assert unknown.Location == config.LOC_INCONNU
    assert fixed.Location == config.LOC_REUNION
