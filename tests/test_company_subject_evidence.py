from cyberwatch import (
    company_evidence,
    company_subject_evidence,
    config,
    official_site_discovery,
)


def test_subject_attribution_accepts_named_victim_activity():
    result = company_subject_evidence.classify_subject_attributed_activity(
        "Intermarché",
        "Intermarché est une enseigne de supermarchés française spécialisée dans le commerce alimentaire.",
    )
    assert result is not None
    assert result[0] == config.SECTOR_RETAIL


def test_subject_attribution_accepts_first_person_activity():
    result = company_subject_evidence.classify_subject_attributed_activity(
        "Acme Cloud",
        "Nous sommes un éditeur de logiciels SaaS et proposons des services cloud aux entreprises.",
    )
    assert result is not None
    assert result[0] == config.SECTOR_TECH


def test_subject_attribution_accepts_observed_long_tail_official_phrasing():
    cases = [
        (
            "KparK",
            "KparK est le spécialiste de la rénovation sur-mesure de l'habitat, fenêtres, volets et portes.",
            config.SECTOR_CONSTRUCTION,
        ),
        (
            "Chupin",
            "Chupin est un fournisseur de matériel agricole et propose des pièces et équipements aux professionnels.",
            config.SECTOR_RETAIL,
        ),
        (
            "Clenet",
            "Clenet est spécialisé dans la manutention industrielle et les équipements destinés aux sites de production.",
            config.SECTOR_INDUSTRY,
        ),
        (
            "EVA Nantes Sud",
            "EVA Nantes Sud est une salle de réalité virtuelle dédiée au free roaming et à l'esport.",
            config.SECTOR_SPORT,
        ),
    ]
    for organisation, text, expected in cases:
        result = company_subject_evidence.classify_subject_attributed_activity(
            organisation, text
        )
        assert result is not None, organisation
        assert result[0] == expected, organisation


def test_subject_attribution_rejects_supplier_activity_stor_regression():
    assert company_subject_evidence.classify_subject_attributed_activity(
        "STOR Solutions",
        "STOR Solutions travaille avec Iagona, son fournisseur, fabricant de solutions libre-service.",
    ) is None


def test_subject_attribution_rejects_partner_activity():
    assert company_subject_evidence.classify_subject_attributed_activity(
        "Acme",
        "Acme s'appuie sur Beta, partenaire spécialisé dans la construction et le génie civil.",
    ) is None


def test_long_tail_patterns_are_not_attributed_to_third_parties():
    cases = [
        (
            "Acme",
            "Acme travaille avec KparK, son fournisseur, spécialiste de la rénovation de l'habitat.",
        ),
        (
            "Acme",
            "Acme travaille avec Chupin, son fournisseur de matériel agricole et de pièces détachées.",
        ),
        (
            "Acme",
            "Acme s'appuie sur Clenet, partenaire spécialisé dans la manutention industrielle.",
        ),
        (
            "Acme",
            "Acme travaille avec EVA Nantes Sud, partenaire exploitant une salle de réalité virtuelle dédiée à l'esport.",
        ),
    ]
    for organisation, text in cases:
        assert company_subject_evidence.classify_subject_attributed_activity(
            organisation, text
        ) is None


def test_virtual_reality_without_esport_is_not_enough_for_sport():
    assert company_subject_evidence.classify_subject_attributed_activity(
        "Acme VR",
        "Acme VR est une salle de réalité virtuelle proposant des expériences immersives.",
    ) is None


def test_agricultural_customer_context_is_not_enough_for_retail():
    assert company_subject_evidence.classify_subject_attributed_activity(
        "Acme",
        "Acme accompagne les exploitations agricoles et leurs fournisseurs dans leur transformation numérique.",
    ) is None


def test_strict_resolver_requires_identity_and_subject(monkeypatch):
    monkeypatch.setattr(
        official_site_discovery,
        "discover_official_sites",
        lambda organisation, hint_urls=(): ["https://www.intermarche.com/"],
    )
    monkeypatch.setattr(
        company_evidence,
        "_page",
        lambda url: (
            "Intermarché - site officiel",
            "Intermarché est une enseigne de supermarchés française.",
            [],
            "https://www.intermarche.com/",
        ),
    )
    evidence = company_subject_evidence.resolve_official_site_subject_attributed(
        "Intermarché"
    )
    assert evidence is not None
    assert evidence.sector == config.SECTOR_RETAIL
    assert evidence.evidence_type == "official_subject_activity"


def test_strict_resolver_rejects_third_party_domain_even_if_text_mentions_victim(monkeypatch):
    monkeypatch.setattr(
        company_evidence,
        "_page",
        lambda url: (
            "Intermarché : présentation",
            "Intermarché est une enseigne de supermarchés française.",
            [],
            url,
        ),
    )
    evidence = company_subject_evidence.resolve_official_site_subject_attributed(
        "Intermarché",
        ["https://actualites-exemple.fr/intermarche"],
    )
    assert evidence is None


def test_strict_resolver_accepts_acronym_domain(monkeypatch):
    assert official_site_discovery.domain_matches_organisation(
        "Bibliothèque Nationale de France", "https://www.bnf.fr/"
    )
    monkeypatch.setattr(
        company_evidence,
        "_page",
        lambda url: (
            "Bibliothèque nationale de France",
            "La Bibliothèque Nationale de France est une institution culturelle publique.",
            [],
            "https://www.bnf.fr/",
        ),
    )
    # Le secteur Culture n'est pas dans les motifs stricts actuels ; le test
    # vérifie donc uniquement que le garde de domaine ne rejette pas l'acronyme.
    assert company_subject_evidence.resolve_official_site_subject_attributed(
        "Bibliothèque Nationale de France", ["https://www.bnf.fr/"]
    ) is None
