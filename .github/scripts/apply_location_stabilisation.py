from __future__ import annotations

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"bloc attendu introuvable dans {path}: {old[:120]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


def append_once(path: str, marker: str, block: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    if marker in text:
        return
    if not text.endswith("\n"):
        text += "\n"
    target.write_text(text + "\n" + block.rstrip() + "\n", encoding="utf-8")


replace_once(
    "cyberwatch/runner.py",
    '''    if location == config.LOC_INCONNU:\n        location = classify_location(\n            text, organisation,\n            entity=territories.get(searchable(organisation), ""),\n            default=spec.location_rule,\n        )\n''',
    '''    if location == config.LOC_INCONNU:\n        # Le défaut de source est volontairement différé : un match entreprise\n        # exact doit pouvoir fournir 974/976 avant le fallback France des\n        # sources nationales. Les indices explicites restent prioritaires.\n        location = classify_location(\n            text, organisation,\n            entity=territories.get(searchable(organisation), ""),\n        )\n''',
)

replace_once(
    "cyberwatch/runner.py",
    '''        if item is not None:\n            items.append(item)\n            if ai_state is not None:\n                ai.qualify_item(item, entry, spec, ai_state)\n            if fact_rows is not None:\n''',
    '''        if item is not None:\n            items.append(item)\n            if ai_state is not None:\n                ai.qualify_item(item, entry, spec, ai_state)\n            # Les appels hors pipeline IA (diagnose/probe/tests ciblés) gardent\n            # le comportement historique : le défaut source reste un dernier\n            # recours, mais il n'est plus appliqué avant l'enrichissement live.\n            if (\n                item.Location == config.LOC_INCONNU\n                and spec.location_rule in config.LOCATIONS\n                and spec.location_rule != config.LOC_INCONNU\n            ):\n                item.Location = spec.location_rule\n            if fact_rows is not None:\n''',
)

replace_once(
    "cyberwatch/ai.py",
    '''    if spec.params.get("skip_ai_qualification"):\n        return\n\n    if item.Sector == config.SECTOR_UNKNOWN or item.Location == config.LOC_INCONNU:\n        _escalate_org_enrichment_deterministic(item, entry, spec, state)\n\n    requested = [\n        name for name in ("Threat", "Sector", "Location")\n        if getattr(item, name) == FIELD_SPECS[name][2]\n    ]\n    if not requested:\n        return\n\n    state.candidates += 1\n    for name in requested:\n        state.unknown_before[name] = state.unknown_before.get(name, 0) + 1\n\n    sector_requested = "Sector" in requested\n''',
    '''    if spec.params.get("skip_ai_qualification"):\n        return\n\n    # Les métriques décrivent l'état à l'entrée du pipeline de qualification,\n    # avant que l'enrichissement entreprise ou un fallback de source ne puisse\n    # résoudre un champ. Cela garantit Unknown_Before >= Qualified par champ.\n    initially_unknown = [\n        name for name in ("Threat", "Sector", "Location")\n        if getattr(item, name) == FIELD_SPECS[name][2]\n    ]\n    if not initially_unknown:\n        return\n    for name in initially_unknown:\n        state.unknown_before[name] = state.unknown_before.get(name, 0) + 1\n\n    if item.Sector == config.SECTOR_UNKNOWN or item.Location == config.LOC_INCONNU:\n        _escalate_org_enrichment_deterministic(item, entry, spec, state)\n\n    # Le défaut géographique déclaré par la source est plus faible qu'un match\n    # entreprise exact, mais doit rester avant le LLM : pas d'appel OpenAI pour\n    # conclure France lorsque la source le garantit déjà par contrat.\n    if (\n        item.Location == config.LOC_INCONNU\n        and spec.location_rule in config.LOCATIONS\n        and spec.location_rule != config.LOC_INCONNU\n    ):\n        item.Location = spec.location_rule\n        state.qualified["Location"] = state.qualified.get("Location", 0) + 1\n\n    requested = [\n        name for name in ("Threat", "Sector", "Location")\n        if getattr(item, name) == FIELD_SPECS[name][2]\n    ]\n    if not requested:\n        return\n\n    state.candidates += 1\n    sector_requested = "Sector" in requested\n''',
)

replace_once(
    "cyberwatch/config.py",
    'METHOD_ID = "OBS-FR-OI-SIMPLE-SOURCING-6"',
    'METHOD_ID = "OBS-FR-OI-SIMPLE-SOURCING-7"',
)

replace_once(
    "tests/test_location_resolution.py",
    'from cyberwatch import ai, config, enrichment, org_enrichment, sources, store\n',
    'from cyberwatch import ai, config, enrichment, org_enrichment, runner, sources, store\n',
)

append_once(
    "tests/test_location_resolution.py",
    "def test_live_frenchbreaches_org_api_beats_france_default",
    r'''
def _live_item(source_id: str, org: str, *, summary: str = "", location: str = ""):
    spec = sources.by_id(source_id)
    assert spec is not None
    entry = RawEntry(
        title=org,
        published="2026-08-16",
        summary=summary,
        organisation=org,
        location=location,
        url=f"https://example.test/{source_id.lower()}",
    )
    item = runner.entry_to_item(entry, spec, "2026-08-16T11:00:00+04:00", {}, {})
    assert item is not None
    return item, entry, spec


def _org_record(org_key: str, organisation_raw: str, fetched_at: str, *, department: str, status: str = org_enrichment.MATCHED):
    return org_enrichment.OrgEnrichmentRecord(
        Organisation_Key=org_key,
        Query_Name=organisation_raw,
        Matched_Name=organisation_raw if status == org_enrichment.MATCHED else "",
        Match_Status=status,
        Headquarters_Department=department,
        Fetched_At=fetched_at,
    )


def test_live_frenchbreaches_org_api_beats_france_default(monkeypatch):
    item, entry, spec = _live_item("FRENCHBREACHES", "Société Réunion Test")
    assert item.Location == config.LOC_INCONNU

    monkeypatch.setattr(
        org_enrichment,
        "resolve",
        lambda org_key, organisation_raw, fetched_at, state: _org_record(
            org_key, organisation_raw, fetched_at, department="974"
        ),
    )
    state = ai.AiRunState(enabled=False, org_enrichment=org_enrichment.OrgEnrichmentState(enabled=True))
    ai.qualify_item(item, entry, spec, state)

    assert item.Location == config.LOC_REUNION


def test_live_bonjourlafuite_org_api_beats_france_default(monkeypatch):
    item, entry, spec = _live_item("BONJOURLAFUITE", "Société Mayotte Test")
    assert item.Location == config.LOC_INCONNU

    monkeypatch.setattr(
        org_enrichment,
        "resolve",
        lambda org_key, organisation_raw, fetched_at, state: _org_record(
            org_key, organisation_raw, fetched_at, department="976"
        ),
    )
    state = ai.AiRunState(enabled=False, org_enrichment=org_enrichment.OrgEnrichmentState(enabled=True))
    ai.qualify_item(item, entry, spec, state)

    assert item.Location == config.LOC_MAYOTTE


def test_live_french_source_metropolitan_headquarters_stays_france(monkeypatch):
    item, entry, spec = _live_item("FRENCHBREACHES", "Société Paris Test")
    calls = []

    def fake_resolve(org_key, organisation_raw, fetched_at, state):
        calls.append(org_key)
        return _org_record(org_key, organisation_raw, fetched_at, department="75")

    monkeypatch.setattr(org_enrichment, "resolve", fake_resolve)
    state = ai.AiRunState(enabled=False, org_enrichment=org_enrichment.OrgEnrichmentState(enabled=True))
    ai.qualify_item(item, entry, spec, state)

    assert calls == [item.Organisation_Key]
    assert item.Location == config.LOC_FRANCE


def test_live_french_source_not_found_falls_back_to_france_without_openai(monkeypatch):
    item, entry, spec = _live_item("FRENCHBREACHES", "Société Introuvable Test")
    monkeypatch.setattr(
        org_enrichment,
        "resolve",
        lambda org_key, organisation_raw, fetched_at, state: _org_record(
            org_key, organisation_raw, fetched_at, department="", status=org_enrichment.NOT_FOUND
        ),
    )
    monkeypatch.setattr(ai, "_call_openai", lambda *a, **k: (_ for _ in ()).throw(AssertionError("appel OpenAI inattendu")))
    state = ai.AiRunState(
        enabled=True,
        api_key="test",
        org_enrichment=org_enrichment.OrgEnrichmentState(enabled=True),
    )
    ai.qualify_item(item, entry, spec, state)

    assert item.Location == config.LOC_FRANCE
    assert state.calls_attempted == 0


def test_live_french_source_ambiguous_falls_back_to_france(monkeypatch):
    item, entry, spec = _live_item("BONJOURLAFUITE", "Société Ambiguë Test")
    monkeypatch.setattr(
        org_enrichment,
        "resolve",
        lambda org_key, organisation_raw, fetched_at, state: _org_record(
            org_key, organisation_raw, fetched_at, department="", status=org_enrichment.AMBIGUOUS
        ),
    )
    state = ai.AiRunState(enabled=False, org_enrichment=org_enrichment.OrgEnrichmentState(enabled=True))
    ai.qualify_item(item, entry, spec, state)

    assert item.Location == config.LOC_FRANCE


def test_live_explicit_reunion_is_never_overwritten_by_metropolitan_api(monkeypatch):
    item, entry, spec = _live_item(
        "FRENCHBREACHES",
        "Société Locale Test",
        summary="Cette entreprise réunionnaise confirme une fuite de données.",
    )
    assert item.Location == config.LOC_REUNION

    monkeypatch.setattr(
        org_enrichment,
        "resolve",
        lambda org_key, organisation_raw, fetched_at, state: _org_record(
            org_key, organisation_raw, fetched_at, department="75"
        ),
    )
    state = ai.AiRunState(enabled=False, org_enrichment=org_enrichment.OrgEnrichmentState(enabled=True))
    ai.qualify_item(item, entry, spec, state)

    assert item.Location == config.LOC_REUNION


def test_live_structured_location_is_never_overwritten_by_org_api(monkeypatch):
    item, entry, spec = _live_item(
        "RANSOMWARE_LIVE",
        "Victime Structurée Test",
        location=config.LOC_REUNION,
    )
    item.Sector = config.SECTOR_UNKNOWN
    assert item.Location == config.LOC_REUNION

    monkeypatch.setattr(
        org_enrichment,
        "resolve",
        lambda org_key, organisation_raw, fetched_at, state: _org_record(
            org_key, organisation_raw, fetched_at, department="75"
        ),
    )
    state = ai.AiRunState(enabled=False, org_enrichment=org_enrichment.OrgEnrichmentState(enabled=True))
    ai.qualify_item(item, entry, spec, state)

    assert item.Location == config.LOC_REUNION


def test_live_cyberattaque_without_org_match_keeps_location_unknown(monkeypatch):
    item, entry, spec = _live_item("CYBERATTAQUE_ORG", "Victime Sans Match Test")
    item.Threat = config.THREAT_LEAK
    item.Sector = config.SECTOR_TECH
    monkeypatch.setattr(org_enrichment, "resolve", lambda *a, **k: None)
    state = ai.AiRunState(enabled=False, org_enrichment=org_enrichment.OrgEnrichmentState(enabled=True))
    ai.qualify_item(item, entry, spec, state)

    assert item.Location == config.LOC_INCONNU


def test_location_metrics_count_org_resolution_from_initial_unknown(monkeypatch):
    item, entry, spec = _live_item("CYBERATTAQUE_ORG", "Victime Métrique API")
    item.Threat = config.THREAT_LEAK
    item.Sector = config.SECTOR_TECH
    monkeypatch.setattr(
        org_enrichment,
        "resolve",
        lambda org_key, organisation_raw, fetched_at, state: _org_record(
            org_key, organisation_raw, fetched_at, department="974"
        ),
    )
    monkeypatch.setattr(store, "save_org_enrichment_cache", lambda rows: None)
    state = ai.AiRunState(enabled=False, org_enrichment=org_enrichment.OrgEnrichmentState(enabled=True))

    ai.qualify_item(item, entry, spec, state)
    usage = ai.finish_run(state, "RUN-TEST-LOCATION-API", item.Collected_As_Of, "CREATE")

    assert state.unknown_before.get("Location") == 1
    assert state.qualified.get("Location") == 1
    assert usage["Location_Unknown_Before"] == 1
    assert usage["Location_Qualified"] == 1
    assert usage["Still_Unknown"] == 0


def test_location_metrics_count_llm_resolution_after_org_miss(monkeypatch):
    item, entry, spec = _live_item(
        "CYBERATTAQUE_ORG",
        "Victime Métrique LLM",
        summary="L'organisation indique être basée à Maurice.",
    )
    item.Threat = config.THREAT_LEAK
    item.Sector = config.SECTOR_TECH
    assert item.Location == config.LOC_INCONNU
    monkeypatch.setattr(org_enrichment, "resolve", lambda *a, **k: None)
    monkeypatch.setattr(
        ai,
        "_call_openai",
        lambda *a, **k: {
            "output": [{
                "type": "message",
                "content": [{
                    "type": "output_text",
                    "text": '{"location":{"value":"Maurice","confidence":0.95,"evidence":"basée à Maurice"}}',
                }],
            }],
            "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
        },
    )
    state = ai.AiRunState(
        enabled=True,
        api_key="test",
        org_enrichment=org_enrichment.OrgEnrichmentState(enabled=True),
    )

    ai.qualify_item(item, entry, spec, state)

    assert item.Location == config.LOC_MAURICE
    assert state.unknown_before.get("Location") == 1
    assert state.qualified.get("Location") == 1


def test_location_metrics_ignore_already_known_location(monkeypatch):
    item, entry, spec = _live_item(
        "RANSOMWARE_LIVE",
        "Victime Métrique Connue",
        location=config.LOC_REUNION,
    )
    item.Threat = config.THREAT_RANSOMWARE
    item.Sector = config.SECTOR_TECH
    monkeypatch.setattr(org_enrichment, "resolve", lambda *a, **k: (_ for _ in ()).throw(AssertionError("resolve inattendu")))
    state = ai.AiRunState(enabled=False, org_enrichment=org_enrichment.OrgEnrichmentState(enabled=True))

    ai.qualify_item(item, entry, spec, state)

    assert state.unknown_before.get("Location", 0) == 0
    assert state.qualified.get("Location", 0) == 0
''',
)
