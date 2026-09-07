import pytest

from cyberwatch.normalize import load_organisation_aliases, organisation_acronym, organisation_key


@pytest.mark.parametrize("left,right", [
    ("ManoMano", "Mano Mano"),
    ("Supreme Body", "Supremebody"),
    ("Productly.app", "Productly"),
    ("ComptoirDuReve.fr", "Comptoir Du Rêve"),
    ("AEFE", "Agence pour l’enseignement français à l’étranger"),
    ("ANCT", "Agence Nationale de la Cohésion des Territoires"),
    ("ONPP", "Ordre national des pédicures-podologues"),
    ("FFHandball", "Fédération Française de Handball"),
    ("Nantes Métropole", "Métropole de Nantes"),
    ("Rennes Métropole", "Métropole de Rennes"),
    ("Cyberattaque à Gagny", "Ville de Gagny"),
    # Stabilisation pré-release : permutation/concaténation certaines
    # observées dans les données réelles, non résolues par la seule
    # normalisation déterministe (§7).
    ("Motoculture Cravero", "Cravero Motoculture"),
    ("FranceCasse", "France Casse"),
    ("DGFiP", "Direction Générale des Finances Publiques"),
    ("Lebonmateriel.fr", "Le Bon Matériel"),
    ("Allopneus", "Allo Pneus"),
    ("MaGestionLocative", "Ma Gestion Locative"),
    ("Groupe Géotec", "Géotec"),
    ("SUEZ", "Suez Eau France"),
    ("IRD", "Institut de recherche pour le développement"),
    # Reset préproduction 2026-08-28 : désignations croisées vérifiées dans
    # les deux sources éditoriales pour le même événement et la même date.
    ("Cloud de l'État", "DINUM"),
    ("NETIM COMPANY", "Netim"),
    ("Solimut", "Solimut Mutuelle"),
    ("Banque Alimentaire de Strasbourg", "Banque Alimentaire de la Croix-Rouge à Strasbourg"),
    ("Docurba.gouv.fr", "Docurba"),
    ("Wesh bien", "WeshBien"),
    ("L.Commerce", "Allo E.Leclerc"),
    ("Eusko", "Euskal Moneta"),
])
def test_versioned_aliases_are_exact(left, right):
    assert organisation_key(left) == organisation_key(right)


def test_alias_conflict_fails_deterministically(tmp_path):
    path = tmp_path / "aliases.csv"
    path.write_text("alias,canonical,reason\nX,One,test\nX,Two,test\n", encoding="utf-8")
    with pytest.raises(ValueError, match="conflictuel"):
        load_organisation_aliases(path)


def test_alias_order_does_not_change_mapping(tmp_path):
    first = tmp_path / "first.csv"
    second = tmp_path / "second.csv"
    first.write_text("alias,canonical,reason\nA,Alpha,x\nB,Beta,x\n", encoding="utf-8")
    second.write_text("alias,canonical,reason\nB,Beta,x\nA,Alpha,x\n", encoding="utf-8")
    assert load_organisation_aliases(first) == load_organisation_aliases(second)


def test_acronym_generation_is_exact_and_deterministic():
    assert organisation_acronym("Agence Nationale de la Cohésion des Territoires") == "ANCT"
    assert organisation_acronym("Ordre national des pédicures-podologues") == "ONPP"
