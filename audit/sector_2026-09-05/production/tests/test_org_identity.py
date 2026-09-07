"""Identité organisationnelle déterministe utilisée par la déduplication."""

import pytest

from cyberwatch import org_identity as oi
from cyberwatch.dedup import MERGE, NO_DECISION, build_incidents, decide_merge
from cyberwatch.identity import incident_id
from cyberwatch.normalize import organisation_key
from cyberwatch.org_identity import effective_organisation_key


@pytest.mark.parametrize(
    "raw",
    [
        "Département de la Gironde",
        "Conseil départemental de la Gironde",
        "Département 33",
        "Conseil départemental 33",
        "CD33",
        "CD 33",
    ],
)
def test_department_name_and_code_resolve_to_same_identity(raw):
    assert effective_organisation_key(raw) == "departement 33"


@pytest.mark.parametrize(
    "raw",
    [
        "Département de La Réunion",
        "Conseil départemental de La Réunion",
        "Département 974",
        "Conseil départemental 974",
        "CD974",
    ],
)
def test_overseas_department_code_is_supported(raw):
    assert effective_organisation_key(raw) == "departement 974"


@pytest.mark.parametrize(
    "raw",
    [
        "Région Île-de-France",
        "Conseil régional d'Île-de-France",
        "Région 11",
        "Conseil régional 11",
        "CR11",
    ],
)
def test_region_name_and_code_resolve_to_same_identity(raw):
    assert effective_organisation_key(raw) == "region 11"


def test_entity_type_is_part_of_identity():
    assert effective_organisation_key("Département 75") == "departement 75"
    assert effective_organisation_key("Région 75") == "region 75"
    assert effective_organisation_key("Département 75") != effective_organisation_key("Région 75")


def test_code_alone_never_identifies_an_organisation():
    assert effective_organisation_key("974") == organisation_key("974")
    assert effective_organisation_key("974") != "departement 974"


def test_unknown_organisation_is_accepted_without_reference_entry():
    raw = "Nouvelle Société Inconnue 2027"
    assert effective_organisation_key(raw) == organisation_key(raw)


def test_ambiguous_business_name_is_not_misread_as_region_code():
    raw = "Region 11 Consulting"
    assert effective_organisation_key(raw) == organisation_key(raw)


def test_bare_commune_keeps_historical_identity_policy():
    raw = "Saint-Denis"
    assert effective_organisation_key(raw) == organisation_key(raw)


def test_singleton_keeps_historical_incident_id_when_identity_resolves(make_item):
    item = make_item(
        source="SOURCE_A",
        org="Département de l’Ardèche",
        published="2026-04-12",
        url="https://a.example/incident",
    )
    effective = effective_organisation_key(item.Organisation_Raw, item.Organisation_Key)
    assert effective == "departement 07"
    assert effective != item.Organisation_Key

    incident = build_incidents([item])[0]
    assert incident.Incident_ID == incident_id(item.Organisation_Key, item.Item_ID)


def test_historical_distinct_keys_merge_at_dedup_time_without_rewriting_items(make_item):
    left = make_item(
        source="SOURCE_A",
        org="Département de la Gironde",
        published="2026-03-01",
        url="https://a.example/incident",
    )
    right = make_item(
        source="SOURCE_B",
        org="Conseil départemental 33",
        published="2026-03-02",
        url="https://b.example/incident",
    )

    # Les clés stockées restent distinctes : la migration ne réécrit donc ni
    # ITEMS ni leurs Item_ID historiques.
    assert left.Organisation_Key != right.Organisation_Key
    assert decide_merge(left, right).action == MERGE

    incidents = build_incidents([left, right])
    assert len(incidents) == 1
    assert incidents[0].Items_Count == 2
    assert incidents[0].Incident_ID == incident_id("departement 33", left.Item_ID)


def test_different_departments_are_not_merged(make_item):
    left = make_item(
        source="SOURCE_A",
        org="Département de la Gironde",
        published="2026-03-01",
        url="https://a.example/incident",
    )
    right = make_item(
        source="SOURCE_B",
        org="Département des Landes",
        published="2026-03-01",
        url="https://b.example/incident",
    )

    assert decide_merge(left, right).action == NO_DECISION
    assert len(build_incidents([left, right])) == 2


# --------------------------------------------------------------------------
# Registre d'identité organisationnelle validé (§Lot 6/7/17)
# --------------------------------------------------------------------------


def _row(alias_key, canonical_key, *, decision="SAME", origin="LLM_CONFIRMED", confidence="0.97"):
    return {
        "Alias_Key": alias_key,
        "Canonical_Key": canonical_key,
        "Alias_Raw": alias_key,
        "Canonical_Raw": canonical_key,
        "Decision": decision,
        "Origin": origin,
        "Confidence": confidence,
        "Evidence": "e",
        "First_Seen": "2026-01-01T00:00:00+00:00",
        "Last_Validated": "2026-01-01T00:00:00+00:00",
        "Model": "gpt-4o-mini",
        "Prompt_Version": "v1",
        "Input_Hash": "h",
    }


def test_registry_persistence(tmp_path):
    from cyberwatch import store

    merged, problems = oi.merge_organisation_identity_rows([], [_row("aliasco", "canonicalco")])
    assert problems == []

    path = tmp_path / "organisation_identity_registry.csv"
    store.write_csv(path, oi.ORGANISATION_IDENTITY_REGISTRY_COLUMNS, merged)

    reloaded = oi.load_organisation_identity_registry(path)
    assert reloaded == {"aliasco": "canonicalco"}


def test_registry_persistence_missing_file_is_empty(tmp_path):
    assert oi.load_organisation_identity_registry(tmp_path / "absent.csv") == {}


def test_registry_convergent_aliases_are_valid():
    """A -> C et B -> C : convergent vers la même cible, valide (§Lot 6)."""
    merged, problems = oi.merge_organisation_identity_rows([], [_row("a", "c"), _row("b", "c")])
    assert problems == []
    assert {row["Alias_Key"]: row["Canonical_Key"] for row in merged} == {"a": "c", "b": "c"}


def test_registry_conflict_rejected():
    """A -> C déjà persisté ; une nouvelle décision A -> D est une collision
    silencieuse potentielle : rejetée explicitement, jamais choisie
    arbitrairement (§Lot 6)."""
    existing = [_row("a", "c")]
    merged, problems = oi.merge_organisation_identity_rows(existing, [_row("a", "d")])
    assert any("collision" in problem for problem in problems)
    assert {row["Alias_Key"]: row["Canonical_Key"] for row in merged} == {"a": "c"}


def test_registry_cycle_rejected():
    """A -> B déjà persisté ; B -> A formerait un cycle direct : rejeté."""
    merged, problems = oi.merge_organisation_identity_rows([_row("a", "b")], [_row("b", "a")])
    assert any("cycle" in problem for problem in problems)
    assert {row["Alias_Key"] for row in merged} == {"a"}


def test_registry_transitive_redirect_is_reflattened():
    """A -> C déjà persisté ; on ajoute C -> D : A doit se résoudre
    directement vers D après fusion, la chaîne restant toujours aplatie à un
    seul saut pour une résolution en O(1) (§Lot 6/7)."""
    existing = [_row("a", "c")]
    merged, problems = oi.merge_organisation_identity_rows(existing, [_row("c", "d")])
    assert problems == []
    by_alias = {row["Alias_Key"]: row["Canonical_Key"] for row in merged}
    assert by_alias["a"] == "d"
    assert by_alias["c"] == "d"


def test_registry_invalid_origin_rejected():
    merged, problems = oi.merge_organisation_identity_rows([], [_row("a", "b", origin="LLM_GUESS")])
    assert merged == []
    assert any("Origin invalide" in problem for problem in problems)


def test_registry_alias_equal_canonical_rejected():
    merged, problems = oi.merge_organisation_identity_rows([], [_row("a", "a")])
    assert merged == []
    assert problems


def test_validate_organisation_identity_registry_reports_collision():
    rows = [_row("a", "c"), _row("a", "d")]
    problems = oi.validate_organisation_identity_registry(rows)
    assert any("collision" in problem for problem in problems)


def test_validate_organisation_identity_registry_accepts_clean_rows():
    rows = [_row("a", "c"), _row("b", "c")]
    assert oi.validate_organisation_identity_registry(rows) == []


def test_effective_org_key_uses_registry(monkeypatch):
    """§Lot 7 : une équivalence validée et présente dans le registre unifie
    la clé effective, sans toucher `Organisation_Key` stockée."""
    monkeypatch.setattr(
        oi, "ORGANISATION_IDENTITY_REGISTRY",
        {"zorglubconsulting": "zorglub consulting"},
    )
    assert oi.effective_organisation_key("ZorglubConsulting") == "zorglub consulting"
    assert oi.effective_organisation_key("Zorglub Consulting") == "zorglub consulting"


def test_registry_never_overrides_territorial_identity(monkeypatch):
    """§Lot 7 : l'ordre de résolution place les identités territoriales
    fortes avant le registre — une entrée de registre mal formée ne peut
    jamais la contourner."""
    monkeypatch.setattr(oi, "ORGANISATION_IDENTITY_REGISTRY", {"departement 33": "autre chose"})
    assert oi.effective_organisation_key("Département de la Gironde") == "departement 33"


def test_effective_org_key_without_registry_entry_is_unaffected(monkeypatch):
    monkeypatch.setattr(oi, "ORGANISATION_IDENTITY_REGISTRY", {"autre alias": "autre canonique"})
    assert oi.effective_organisation_key("Zorglub Consulting") == "zorglub consulting"
