from cyberwatch import store


def _workflow() -> str:
    return (store.ROOT / ".github" / "workflows" / "rebuild-baseline-once.yml").read_text(
        encoding="utf-8"
    )


def test_rebuild_requires_explicit_marker_and_uninitialized_preflight():
    workflow = _workflow()
    assert 'paths:\n      - ".github/rebuild-request"' in workflow
    assert "Vérifier l'état UNINITIALIZED après purge" in workflow
    assert "python -m cyberwatch check --allow-uninitialized" in workflow
    assert workflow.index("Purge locale des artefacts reconstructibles") < workflow.index(
        "Vérifier l'état UNINITIALIZED après purge"
    ) < workflow.index("CREATE from scratch")


def test_rebuild_checks_persisted_incident_projection_before_quality_gate():
    workflow = _workflow()
    assert "build_incidents(items)" in workflow
    assert "identity.incidents_hash(persisted)" in workflow
    assert "identity.incidents_hash(rebuilt)" in workflow
    assert workflow.index("Vérifier la projection ITEMS vers INCIDENTS") < workflow.index(
        "Gate qualité pré-publication"
    )


def test_rebuild_regenerates_dedup_audit_from_rebuilt_items():
    workflow = _workflow()
    assert "data/dedup_audit_candidates.csv" in workflow
    assert "python scripts/export_dedup_audit.py" in workflow
    assert "--items data/items.csv" in workflow
    assert "--output data/dedup_audit_candidates.csv" in workflow
    assert workflow.index("Purge locale des artefacts reconstructibles") < workflow.index(
        "CREATE from scratch"
    ) < workflow.index("Régénérer l'audit dedup du rebuild") < workflow.index(
        "Exporter la DB validée"
    )


def test_rebuild_preserves_diagnostics_on_failure():
    workflow = _workflow()
    assert "if: always()" in workflow
    assert "data/source_facts_ai_cache.json" in workflow
    assert "data/items.csv" in workflow
    assert "data/incidents.csv" in workflow
    assert "data/dedup_audit_candidates.csv" in workflow
