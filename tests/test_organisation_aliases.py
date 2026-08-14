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
