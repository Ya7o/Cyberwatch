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
            "KparK - N°1 de la rénovation de l'habitat, fenêtres, volets et portes sur-mesure.",
            config.SECTOR_CONSTRUCTION,
        ),
        (
            "Chupin",
            "La SARL CHUPIN vous propose une large gamme de matériel agricole de qualité.",
            config.SECTOR_RETAIL,
        ),
        (
            "Clenet",
            "CLENET - Vente et Location de solutions de manutention.",
            config.SECTOR_RETAIL,
        ),
        (
            "EVA Nantes Sud",
            "Salles VR à Nantes | EVA Nantes Sud - Free roaming & esport en réalité virtuelle.",
            config.SECTOR_SPORT,
        ),
    ]
    for organisation, text, expected in cases:
        result = company_subject_evidence.classify_subject_attributed_activity(
            organisation, text
        )
        assert result is not None, organisation
        assert result[0] == expected, organisation


def test_strong_subject_activity_accepts_explicit_construction_leadership():
    result = company_subject_evidence.strong_subject_attributed_activity(
        "Acme Groupe",
        "Acme Groupe, leader européen du BTP et des concessions, développe les villes et territoires.",
    )
    assert result is not None
    assert result[0] == config.SECTOR_CONSTRUCTION


def test_strong_subject_activity_rejects_generic_weak_construction_mention():
    assert company_subject_evidence.strong_subject_attributed_activity(
        "Acme",
        "Acme accompagne ses clients dans leurs projets de construction.",
    ) is None


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
            "Acme s'appuie sur Clenet, partenaire qui assure la vente et location de solutions de manutention.",
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


def test_industry_customer_pages_do_not_make_clenet_industry():
    result = company_subject_evidence.classify_subject_attributed_activity(
        "Clenet",
        "CLENET - Vente et Location de solutions de manutention pour vos besoins en industrie, bâtiment et agriculture.",
    )
    assert result is not None
    assert result[0] == config.SECTOR_RETAIL


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
    assert company_subject_evidence.resolve_official_site_subject_attributed(
        "Bibliothèque Nationale de France", ["https://www.bnf.fr/"]
    ) is None


def test_resolver_searches_same_domain_activity_pages_when_homepage_is_generic(monkeypatch):
    homepage = "https://www.acme.com/"
    activity_page = "https://www.acme.com/en/group/activities"

    monkeypatch.setattr(
        official_site_discovery,
        "discover_official_sites",
        lambda organisation, hint_urls=(): [homepage],
    )

    def fake_page(url):
        if url == homepage:
            return (
                "Acme Group",
                "Acme Group is an international group serving customers worldwide.",
                [],
                homepage,
            )
        if url == activity_page:
            return (
                "Acme Group activities",
                "Acme Group is a European leader in construction and public works.",
                [],
                activity_page,
            )
        return "", "", [], url

    monkeypatch.setattr(company_evidence, "_page", fake_page)
    monkeypatch.setattr(
        company_evidence,
        "_search_links",
        lambda query: [("Acme Group activities", activity_page)],
    )

    evidence = company_subject_evidence.resolve_official_site_subject_attributed("Acme Group")
    assert evidence is not None
    assert evidence.sector == config.SECTOR_CONSTRUCTION
    assert evidence.evidence_url == activity_page


def test_same_domain_activity_search_rejects_external_results(monkeypatch):
    monkeypatch.setattr(
        company_evidence,
        "_search_links",
        lambda query: [("Acme activities", "https://example.org/acme-activities")],
    )
    assert company_subject_evidence._same_domain_activity_pages(
        "Acme", "https://www.acme.com/"
    ) == []
