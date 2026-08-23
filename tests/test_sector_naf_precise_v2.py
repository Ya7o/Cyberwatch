from cyberwatch import config, organisation_sector as osec
from cyberwatch.sector_completion import SECTOR_AGRICULTURE, SECTOR_HOSPITALITY


def test_agriculture_family():
    assert osec.precise_naf_sector("01.11Z") == SECTOR_AGRICULTURE
    assert osec.precise_naf_sector("02.10Z") == SECTOR_AGRICULTURE
    assert osec.precise_naf_sector("03.22Z") == SECTOR_AGRICULTURE


def test_industry_family():
    assert osec.precise_naf_sector("10.11Z") == config.SECTOR_INDUSTRY
    assert osec.precise_naf_sector("25.62Z") == config.SECTOR_INDUSTRY
    assert osec.precise_naf_sector("33.20A") == config.SECTOR_INDUSTRY


def test_energy_family():
    for code in ("35.11Z", "36.00Z", "37.00Z", "38.11Z", "39.00Z"):
        assert osec.precise_naf_sector(code) == config.SECTOR_ENERGY


def test_construction_family():
    for code in ("41.20A", "42.11Z", "43.99B"):
        assert osec.precise_naf_sector(code) == config.SECTOR_CONSTRUCTION


def test_retail_family():
    for code in ("45.11Z", "46.90Z", "47.11A"):
        assert osec.precise_naf_sector(code) == config.SECTOR_RETAIL


def test_transport_family():
    for code in ("49.41A", "50.10Z", "51.10Z", "52.10A", "53.20Z"):
        assert osec.precise_naf_sector(code) == config.SECTOR_TRANSPORT


def test_hospitality_family():
    for code in ("55.10Z", "56.10A", "79.11Z"):
        assert osec.precise_naf_sector(code) == SECTOR_HOSPITALITY


def test_tech_family_is_restricted_to_discriminant_subclasses():
    assert osec.precise_naf_sector("62.01Z") == config.SECTOR_TECH
    assert osec.precise_naf_sector("61.10Z") == config.SECTOR_TECH
    assert osec.precise_naf_sector("63.11Z") == config.SECTOR_TECH
    # 63.9 (portails web, autres services d'information) reste hors périmètre :
    # section J entière volontairement non généralisée.
    assert osec.precise_naf_sector("63.99Z") == config.SECTOR_UNKNOWN
    assert osec.precise_naf_sector("60.10Z") == config.SECTOR_UNKNOWN


def test_finance_family_excludes_holdings():
    assert osec.precise_naf_sector("64.19Z") == config.SECTOR_FINANCE
    assert osec.precise_naf_sector("65.12Z") == config.SECTOR_FINANCE
    assert osec.precise_naf_sector("66.19B") == config.SECTOR_FINANCE
    # Holdings / structures purement patrimoniales : jamais le métier réel.
    assert osec.precise_naf_sector("64.20Z") == config.SECTOR_UNKNOWN
    assert osec.precise_naf_sector("64.30Z") == config.SECTOR_UNKNOWN
    assert osec.precise_naf_sector("70.10Z") == config.SECTOR_UNKNOWN


def test_services_family_strong_subclasses_only():
    # 70.2 (conseil de gestion) couvre 70.21 (relations publiques) et 70.22
    # (conseil pour les affaires) ; seul 70.1 (sièges sociaux) en est exclu.
    for code in ("69.10Z", "69.20Z", "70.21Z", "70.22Z", "78.10Z", "80.10Z", "81.10Z"):
        assert osec.precise_naf_sector(code) == config.SECTOR_SERVICES


def test_education_family():
    assert osec.precise_naf_sector("85.31Z") == config.SECTOR_EDUCATION


def test_health_family_does_not_generalize_social_action():
    assert osec.precise_naf_sector("86.10Z") == config.SECTOR_HEALTH
    assert osec.precise_naf_sector("86.21Z") == config.SECTOR_HEALTH
    # Action sociale (division 87/88) n'est pas généralisée à Santé.
    assert osec.precise_naf_sector("87.10A") == config.SECTOR_UNKNOWN
    assert osec.precise_naf_sector("88.10A") == config.SECTOR_UNKNOWN


def test_ambiguous_and_invalid_codes_stay_unknown():
    assert osec.precise_naf_sector("") == config.SECTOR_UNKNOWN
    assert osec.precise_naf_sector(None) == config.SECTOR_UNKNOWN
    assert osec.precise_naf_sector("XX.99Z") == config.SECTOR_UNKNOWN
    assert osec.precise_naf_sector("94.99Z") == config.SECTOR_UNKNOWN
    assert osec.precise_naf_sector("68.20A") == config.SECTOR_UNKNOWN


def test_naf_codes_with_or_without_punctuation_are_equivalent():
    assert osec.precise_naf_sector("6201Z") == osec.precise_naf_sector("62.01Z")
    assert osec.precise_naf_sector(" 62.01Z ") == config.SECTOR_TECH
