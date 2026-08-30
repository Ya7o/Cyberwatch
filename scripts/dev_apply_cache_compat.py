from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"anchor not found in {path}: {old[:100]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


path = "cyberwatch/organisation_sector_llm.py"
replace_once(
    path,
    '''def compute_input_hash(context: OrganisationContext, *, model: str, prompt_version: str) -> str:\n    """Hash déterministe : organisation + contexte transmis + taxonomie +\n    modèle + version de prompt (§18 du plan). Un cache hit n'appelle jamais\n    le LLM à nouveau."""\n    payload = {\n        "context": context.to_payload(),\n        "taxonomy": list(config.SECTORS),\n        "model": model,\n        "prompt_version": prompt_version,\n    }\n    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))\n    return hashlib.sha256(blob.encode("utf-8")).hexdigest()\n''',
    '''def _compute_input_hash_payload(\n    context_payload: dict, *, taxonomy: list[str], model: str, prompt_version: str,\n) -> str:\n    payload = {\n        "context": context_payload,\n        "taxonomy": list(taxonomy),\n        "model": model,\n        "prompt_version": prompt_version,\n    }\n    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))\n    return hashlib.sha256(blob.encode("utf-8")).hexdigest()\n\n\ndef compute_input_hash(context: OrganisationContext, *, model: str, prompt_version: str) -> str:\n    """Hash déterministe du contrat LLM courant."""\n    return _compute_input_hash_payload(\n        context.to_payload(), taxonomy=list(config.SECTORS), model=model,\n        prompt_version=prompt_version,\n    )\n\n\n# Contrat de migration explicitement borné. Le passage 2026-08-28.8 ->\n# 2026-08-30.9 a ajouté Association / Syndicat à la taxonomie et\n# organisation_family aux outcomes de contexte. Il ne doit pas effacer une\n# décision positive si le contexte métier sous-jacent est strictement le même.\n+LEGACY_COMPATIBLE_PROMPT_VERSIONS = frozenset({"2026-08-28.8"})\n\n\ndef _legacy_compatible_input_hash(\n    context: OrganisationContext, *, model: str, prompt_version: str,\n) -> str:\n    if prompt_version not in LEGACY_COMPATIBLE_PROMPT_VERSIONS:\n        return ""\n    payload = context.to_payload()\n    payload["evidence_stage_outcomes"] = [\n        value for value in payload.get("evidence_stage_outcomes", [])\n        if value.get("type") != osec.EVIDENCE_ORGANISATION_FAMILY\n    ]\n    legacy_taxonomy = [\n        sector for sector in config.SECTORS if sector != config.SECTOR_ASSOCIATION\n    ]\n    return _compute_input_hash_payload(\n        payload, taxonomy=legacy_taxonomy, model=model, prompt_version=prompt_version,\n    )\n'''.replace('\n+LEGACY', '\nLEGACY'),
)

replace_once(
    path,
    '''def call_llm_batch(\n''',
    '''def _legacy_candidate_has_current_support(\n    context: OrganisationContext, candidate: LlmOrganisationCandidate,\n) -> bool:\n    """Ne migre une ancienne décision que si sa base existe encore."""\n    evidence_types = set(context.evidence_types)\n    if candidate.basis == "explicit_activity":\n        return bool(context.activity_descriptions) or bool(\n            evidence_types & {"source_activity", "official_subject_activity"}\n        )\n    if candidate.basis == "structured_metadata":\n        return "structured_source" in evidence_types\n    if candidate.basis == "naf_support":\n        return bool(context.activity_code or context.activity_label)\n    if candidate.basis == "multiple_signals":\n        return len(context.evidence_details) >= 2\n    return False\n\n\ndef _migrate_legacy_positive_cache(\n    cached: dict, context: OrganisationContext, *, current_input_hash: str,\n    effective_model: str, current_prompt_version: str,\n) -> dict | None:\n    """Migration sûre du cache positif 2026-08-28.8.\n\n    Le vieux hash est recalculé avec l'ancien contrat exact. Un hit prouve que\n    le contexte métier n'a pas changé ; seuls la taxonomie, le prompt et la\n    nouvelle étape organisation_family expliquent alors l'invalidation.\n    """\n    if current_prompt_version != PROMPT_VERSION:\n        return None\n    legacy_prompt = str(cached.get("Prompt_Version") or "").strip()\n    cached_model = str(cached.get("Model") or "").strip()\n    if legacy_prompt not in LEGACY_COMPATIBLE_PROMPT_VERSIONS or cached_model != effective_model:\n        return None\n    if _cached_decision_outcome(cached) != "PRODUCED":\n        return None\n    if cached.get("Input_Hash") != _legacy_compatible_input_hash(\n        context, model=cached_model, prompt_version=legacy_prompt,\n    ):\n        return None\n\n    sector = str(cached.get("Sector") or "").strip()\n    basis = str(cached.get("Basis") or "").strip()\n    try:\n        confidence = float(cached.get("Confidence") or 0.0)\n    except (TypeError, ValueError):\n        return None\n    if (\n        sector not in config.SECTORS or sector == config.SECTOR_UNKNOWN\n        or basis not in ACTIONABLE_BASIS_VALUES\n        or confidence < MIN_ACTIONABLE_CONFIDENCE\n    ):\n        return None\n\n    candidate = LlmOrganisationCandidate(\n        context.organisation_key, sector, confidence, basis,\n        str(cached.get("Reason") or "").strip(),\n    )\n    if not _legacy_candidate_has_current_support(context, candidate):\n        return None\n    if not _taxonomy_supports_candidate(context, candidate):\n        return None\n\n    # Le nouveau prompt corrige précisément les associations/syndicats forcés\n    # auparavant vers Services aux entreprises : ces cas doivent être rejoués,\n    # jamais migrés automatiquement.\n    social_text = searchable(" ".join([\n        context.organisation, *context.activity_descriptions,\n        *(str(value.get("text") or "") for value in context.evidence_details),\n    ]))\n    social_markers = (\n        "association", "syndicat", "syndicale", "confederation syndicale",\n        "federation syndicale", "union syndicale", "caritative",\n    )\n    if sector == config.SECTOR_SERVICES and any(marker in social_text for marker in social_markers):\n        return None\n\n    migrated = dict(cached)\n    migrated.update({\n        "Input_Hash": current_input_hash,\n        "Model": effective_model,\n        "Prompt_Version": current_prompt_version,\n        "Decision_Status": "PRODUCED",\n        "Execution_Status": "CACHE_COMPATIBLE_REUSE",\n    })\n    return migrated\n\n\ndef call_llm_batch(\n''',
)

replace_once(
    path,
    '''class EnrichmentReport:\n    organisations_selected: int = 0\n    cache_hits: int = 0\n    cache_misses: int = 0\n''',
    '''class EnrichmentReport:\n    organisations_selected: int = 0\n    cache_hits: int = 0\n    compatible_cache_hits: int = 0\n    cache_misses: int = 0\n''',
)

replace_once(
    path,
    '''        if not force and cached is not None and cached.get("Input_Hash") == input_hash and cached_outcome:\n            report.cache_hits += 1\n            report.outcomes[key] = cached_outcome\n            if cached_outcome == "NO_MATCH":\n                report.abstentions += 1\n            continue\n        # Une entrée périmée ne doit pas être réinjectée si le nouvel appel\n''',
    '''        if not force and cached is not None and cached.get("Input_Hash") == input_hash and cached_outcome:\n            report.cache_hits += 1\n            report.outcomes[key] = cached_outcome\n            if cached_outcome == "NO_MATCH":\n                report.abstentions += 1\n            continue\n        if not force and cached is not None:\n            migrated = _migrate_legacy_positive_cache(\n                cached, context, current_input_hash=input_hash,\n                effective_model=effective_model, current_prompt_version=prompt_version,\n            )\n            if migrated is not None:\n                updated_rows[key] = migrated\n                report.cache_hits += 1\n                report.compatible_cache_hits += 1\n                report.outcomes[key] = "PRODUCED"\n                continue\n        # Une entrée périmée ne doit pas être réinjectée si le nouvel appel\n''',
)

# La forme éditoriale « La Ville de X » est elle aussi auto-descriptive.
replace_once(
    "reference/organisation_families.csv",
    "mairie de|ville de|commune de|conseil departemental",
    "mairie de|ville de|la ville de|commune de|conseil departemental",
)

# Tests unitaires de la migration contractuelle.
test_path = Path("tests/test_organisation_sector_llm.py")
test_text = test_path.read_text(encoding="utf-8")
anchor = '''def test_stale_cache_is_a_miss_and_is_not_reinjected(make_item):\n'''
if anchor not in test_text:
    raise SystemExit("test anchor missing")
insert = r'''def _legacy_cache_row(osl, context, *, sector, basis="explicit_activity", confidence="0.90"):
    prompt = "2026-08-28.8"
    model = "gpt-5-nano"
    return {
        "Organisation_Key": context.organisation_key,
        "Organisation": context.organisation,
        "Input_Hash": osl._legacy_compatible_input_hash(context, model=model, prompt_version=prompt),
        "Sector": sector,
        "Confidence": confidence,
        "Basis": basis,
        "Reason": "décision historique corroborée",
        "Model": model,
        "Prompt_Version": prompt,
        "Created_At": "2026-08-30T11:03:45+00:00",
    }


def test_legacy_positive_cache_is_migrated_when_business_context_is_identical(make_item):
    item = make_item(org="Easypara", sector=config.SECTOR_UNKNOWN)
    facts = [{
        "Item_ID": item.Item_ID,
        "Activity_Description": "vente en ligne de produits",
        "Activity_Sector_Match": config.SECTOR_COMMERCE,
    }]
    evidence = osec.collect_organisation_evidence(
        [item], reference={}, source_fact_rows=facts, org_cache_rows=[],
        domain_page_rows=[], llm_cache_rows=[],
    )
    context = osl.build_organisation_context(
        item.Organisation_Key, [item], source_fact_rows=facts, org_cache_rows=[],
        evidence=evidence[item.Organisation_Key],
    )
    legacy = _legacy_cache_row(osl, context, sector=config.SECTOR_COMMERCE)

    report = osl.enrich_unknown_organisation_sectors(
        [item], reference={}, source_fact_rows=facts, org_cache_rows=[],
        domain_page_rows=[], cache_rows=[legacy], no_llm=True, persist=False,
    )

    assert report.cache_hits == 1
    assert report.compatible_cache_hits == 1
    assert report.cache_misses == 0
    assert report.outcomes[item.Organisation_Key] == "PRODUCED"
    row = report.cache_rows[0]
    assert row["Sector"] == config.SECTOR_COMMERCE
    assert row["Prompt_Version"] == osl.PROMPT_VERSION
    assert row["Decision_Status"] == "PRODUCED"
    assert row["Execution_Status"] == "CACHE_COMPATIBLE_REUSE"
    assert row["Input_Hash"] == osl.compute_input_hash(
        context, model="gpt-5-nano", prompt_version=osl.PROMPT_VERSION,
    )


def test_legacy_cache_is_not_migrated_when_context_changed(make_item):
    item = make_item(org="Easypara", sector=config.SECTOR_UNKNOWN)
    old_facts = [{
        "Item_ID": item.Item_ID,
        "Activity_Description": "vente en ligne de produits",
        "Activity_Sector_Match": config.SECTOR_COMMERCE,
    }]
    old_evidence = osec.collect_organisation_evidence(
        [item], reference={}, source_fact_rows=old_facts, org_cache_rows=[],
        domain_page_rows=[], llm_cache_rows=[],
    )
    old_context = osl.build_organisation_context(
        item.Organisation_Key, [item], source_fact_rows=old_facts, org_cache_rows=[],
        evidence=old_evidence[item.Organisation_Key],
    )
    legacy = _legacy_cache_row(osl, old_context, sector=config.SECTOR_COMMERCE)
    new_facts = [{
        "Item_ID": item.Item_ID,
        "Activity_Description": "service de télémédecine",
        "Activity_Sector_Match": config.SECTOR_HEALTH,
    }]

    report = osl.enrich_unknown_organisation_sectors(
        [item], reference={}, source_fact_rows=new_facts, org_cache_rows=[],
        domain_page_rows=[], cache_rows=[legacy], no_llm=True, persist=False,
    )
    assert report.compatible_cache_hits == 0
    assert report.cache_misses == 1
    assert report.cache_rows == []


def test_legacy_services_cache_for_social_context_requires_fresh_decision(make_item):
    item = make_item(org="Association Exemple", sector=config.SECTOR_UNKNOWN)
    facts = [{
        "Item_ID": item.Item_ID,
        "Activity_Description": "association caritative d'aide alimentaire",
        "Activity_Sector_Match": config.SECTOR_SERVICES,
    }]
    evidence = osec.collect_organisation_evidence(
        [item], reference={}, source_fact_rows=facts, org_cache_rows=[],
        domain_page_rows=[], llm_cache_rows=[],
    )
    context = osl.build_organisation_context(
        item.Organisation_Key, [item], source_fact_rows=facts, org_cache_rows=[],
        evidence=evidence[item.Organisation_Key],
    )
    legacy = _legacy_cache_row(osl, context, sector=config.SECTOR_SERVICES)
    report = osl.enrich_unknown_organisation_sectors(
        [item], reference={}, source_fact_rows=facts, org_cache_rows=[],
        domain_page_rows=[], cache_rows=[legacy], no_llm=True, persist=False,
    )
    assert report.compatible_cache_hits == 0
    assert report.cache_misses == 1
    assert report.cache_rows == []


'''
test_path.write_text(test_text.replace(anchor, insert + anchor, 1), encoding="utf-8")

# Ajoute le cas éditorial La Ville de Tarnos au référentiel.
family_test = Path("tests/test_organisation_family.py")
text = family_test.read_text(encoding="utf-8")
old = '    ("Préfecture de la Moselle", "FR_PREFECTURE", config.SECTOR_ADMIN),\n'
new = old + '    ("La Ville de Tarnos", "FR_LOCAL_AUTHORITY", config.SECTOR_ADMIN),\n'
if old not in text:
    raise SystemExit("family test anchor missing")
family_test.write_text(text.replace(old, new, 1), encoding="utf-8")

method = Path("METHODOLOGY.md")
with method.open("a", encoding="utf-8") as handle:
    handle.write("\n\n#### Compatibilité du cache Sector\n\nUne évolution de prompt ou de taxonomie n'autorise jamais la réinjection aveugle d'un cache LLM. Pour le contrat 2026-08-28.8, Cyberwatch sait recalculer l'ancien Input_Hash en retirant uniquement les dimensions ajoutées par la migration (catégorie Association / Syndicat et outcome organisation_family). Une décision positive n'est réutilisée que si ce hash historique correspond exactement au contexte courant, si sa base est encore présente et si la nouvelle politique de taxonomie ne l'invalide pas. La ligne est alors migrée vers le hash courant avec Execution_Status=CACHE_COMPATIBLE_REUSE ; sinon elle reste un cache miss et doit être rejouée.\n")

print("cache compatibility patch applied")
