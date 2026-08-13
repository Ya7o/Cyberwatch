"""Régressions de normalisation prouvées par l'audit multi-source."""

from cyberwatch.collectors.ransomware_live import _victim_name
from cyberwatch.collectors.cyberattaque_org import organisation_from_title, repair_existing_identities
from cyberwatch.normalize import organisation_key


def test_duvignau_40_has_one_deterministic_key():
    assert organisation_key("Duvignau40") == organisation_key("Duvignau 40")


def test_incident_suffix_is_not_part_of_the_victim_identity():
    assert organisation_key("AFPA piraté") == organisation_key("AFPA")


def test_ransomware_domain_is_canonicalized_before_identity():
    assert organisation_key(_victim_name("reflet2000.fr")) == organisation_key("Reflet 2000")

def test_cyberattaque_title_extracts_the_victim_prefix():
    assert organisation_from_title("GitHub touché par une cyberattaque") == "GitHub"


def test_cyberattaque_removes_compound_editorial_tail_before_victim():
    assert organisation_from_title("Biosynex annonce être victime d’une fuite") == "Biosynex"


def test_cyberattaque_removes_informs_clients_editorial_tail():
    assert organisation_from_title("Europ Camera informe ses clients d’une fuite") == "Europ Camera"


def test_cyberattaque_removes_opens_breach_series_editorial_tail():
    assert organisation_from_title("Roussel Agri62 ouvre la série de fuites BLGCloud") == "Roussel Agri62"
    assert organisation_from_title("Roussel Agri62 ouvre la serie de fuites BLGCloud") == "Roussel Agri62"


def test_cyberattaque_does_not_truncate_a_name_without_editorial_tail():
    assert organisation_from_title("Annonce France : incident de sécurité") == "Annonce France"


def test_existing_cyberattaque_item_is_repaired_with_a_new_identity(make_item):
    item = make_item(
        source="CYBERATTAQUE_ORG", org="Biosynex annonce être",
        url="https://example.org/biosynex", title="Biosynex annonce être victime d’une fuite",
    )
    repaired, changed = repair_existing_identities([item])
    assert changed == 1
    assert repaired[0].Organisation_Raw == "Biosynex"
    assert repaired[0].Organisation_Key == "biosynex"


def test_cyberattaque_extracts_victim_named_after_editorial_headline():
    title = "Détenteurs d’armes à nouveau dans le viseur : l’Armurerie Lavaux confirme une cyberattaque"
    assert organisation_from_title(title) == "Armurerie Lavaux"


def test_validated_source_variants_share_one_identity():
    assert organisation_key("Actini Group") == organisation_key("actini")
    assert organisation_key("Chambre de Commerce et de l’Industrie Nice Côte d’Azur") == organisation_key("Chambre de Commerce et d'Industrie Nice Côte d'Azur")
    assert organisation_key("Ministère de l'Éducation nationale") == organisation_key("Éducation Nationale")


def test_ambiguous_ministry_name_remains_distinct():
    assert organisation_key("Ministère de l'Éducation") != organisation_key("Éducation Nationale")

def test_ransomware_technical_suffix_is_removed():
    assert _victim_name("PC SOFT FRANCE - Leaked data") == "PC SOFT FRANCE"


def test_terminal_domain_is_not_part_of_the_organisation_identity():
    assert organisation_key("Booking.com") == organisation_key("Booking")
    assert organisation_key("Location-etudiant.fr") == organisation_key("Location-Etudiant")


def test_validated_spacing_variants_share_one_identity():
    assert organisation_key("Easy Lounge") == organisation_key("EasyLounge")
    assert organisation_key("Move Up Formation") == organisation_key("MoveUp Formation")
