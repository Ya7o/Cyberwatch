from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"replacement attendu une fois dans {path}, trouvé {count}")
    p.write_text(text.replace(old, new), encoding="utf-8")


replace_once(
    "cyberwatch/config.py",
    'METHOD_ID = "OBS-FR-OI-SIMPLE-SOURCING-5"',
    'METHOD_ID = "OBS-FR-OI-SIMPLE-SOURCING-6"',
)

replace_once(
    "cyberwatch/ai.py",
    "    if item.Sector == config.SECTOR_UNKNOWN:\n        _escalate_sector_deterministic(item, entry, spec, state)\n",
    "    if item.Sector == config.SECTOR_UNKNOWN or item.Location == config.LOC_INCONNU:\n        _escalate_org_enrichment_deterministic(item, entry, spec, state)\n",
)

old_fn = '''def _escalate_sector_deterministic(item: Item, entry: RawEntry, spec: SourceSpec, state: AiRunState) -> None:\n    \"\"\"Phase 1 (§Sector fiabilité) : enrichissement gratuit d'entreprise +\n    mapping NAF déterministe, toujours tenté avant tout appel LLM — jamais\n    de LLM ici. Ne lève jamais, ne devine jamais : une étape infructueuse\n    laisse Secteur à Inconnu (`_escalate_sector_llm`, Phase 3, pourra\n    ensuite prendre le relais en dernier recours).\n    \"\"\"\n    if item.Sector != config.SECTOR_UNKNOWN:\n        return\n    org_state = state.org_enrichment\n    if not org_state.enabled:\n        return\n\n    record = org_enrichment.resolve(\n        item.Organisation_Key, item.Organisation_Raw, item.Collected_As_Of, org_state\n    )\n    if record is None or record.Match_Status != org_enrichment.MATCHED or not record.Activity_Label:\n        # AMBIGUOUS/NOT_FOUND/ERROR/budget épuisé -> Inconnu reste Inconnu,\n        # jamais de choix arbitraire.\n        return\n\n    if record.Validated_Sector:\n        item.Sector = record.Validated_Sector\n        state.sector_resolved_enrichment_cache += 1\n        state.qualified[\"Sector\"] = state.qualified.get(\"Sector\", 0) + 1\n        return\n\n    # Mapping déterministe — table dédiée aux 21 sections NAF\n    # (org_enrichment.NAF_SECTIONS), pas classify_sector() : ce dernier est\n    # réglé sur du texte libre d'article et fait correspondre \"distribution\"\n    # à Commerce, ce qui classerait à tort \"Production et distribution\n    # d'électricité...\" en Commerce au lieu d'Énergie (constaté au premier\n    # benchmark réel, cf. org_enrichment.py).\n    sector = org_enrichment.sector_for_activity_label(record.Activity_Label)\n    if sector == config.SECTOR_UNKNOWN:\n        # Pas de correspondance déterministe : `record` reste en cache tel\n        # que `resolve()` l'y a déjà placé (Activity_Label, Match_Status...).\n        # `_escalate_sector_llm` (Phase 3) pourra le relire sans nouvelle\n        # requête HTTP.\n        return\n\n    item.Sector = sector\n    record.Validated_Sector = sector\n    record.Validated_Via = \"deterministic\"\n    record.Cache_Version = org_enrichment.ORG_ENRICHMENT_CACHE_VERSION\n    org_state.cache[item.Organisation_Key] = asdict(record)\n    state.sector_resolved_enriched_deterministic += 1\n    state.qualified[\"Sector\"] = state.qualified.get(\"Sector\", 0) + 1\n'''

new_fn = '''def _escalate_org_enrichment_deterministic(\n    item: Item, entry: RawEntry, spec: SourceSpec, state: AiRunState\n) -> None:\n    \"\"\"Enrichissement organisation unique pour Sector et Location.\n\n    Un seul `resolve()` est tenté lorsque l'un des deux champs est encore\n    inconnu. Le même match exact peut fournir le secteur via la section NAF\n    et la localisation via le département du siège. Aucune valeur déjà connue\n    n'est écrasée et AMBIGUOUS/NOT_FOUND/ERROR ne produisent aucune inférence.\n    \"\"\"\n    if item.Sector != config.SECTOR_UNKNOWN and item.Location != config.LOC_INCONNU:\n        return\n    org_state = state.org_enrichment\n    if not org_state.enabled:\n        return\n\n    record = org_enrichment.resolve(\n        item.Organisation_Key, item.Organisation_Raw, item.Collected_As_Of, org_state\n    )\n    if record is None or record.Match_Status != org_enrichment.MATCHED:\n        return\n\n    if item.Location == config.LOC_INCONNU:\n        location = org_enrichment.location_for_headquarters_department(\n            record.Headquarters_Department\n        )\n        if location != config.LOC_INCONNU:\n            item.Location = location\n            state.qualified[\"Location\"] = state.qualified.get(\"Location\", 0) + 1\n\n    if item.Sector != config.SECTOR_UNKNOWN or not record.Activity_Label:\n        return\n\n    if record.Validated_Sector:\n        item.Sector = record.Validated_Sector\n        state.sector_resolved_enrichment_cache += 1\n        state.qualified[\"Sector\"] = state.qualified.get(\"Sector\", 0) + 1\n        return\n\n    sector = org_enrichment.sector_for_activity_label(record.Activity_Label)\n    if sector == config.SECTOR_UNKNOWN:\n        return\n\n    item.Sector = sector\n    record.Validated_Sector = sector\n    record.Validated_Via = \"deterministic\"\n    record.Cache_Version = org_enrichment.ORG_ENRICHMENT_CACHE_VERSION\n    org_state.cache[item.Organisation_Key] = asdict(record)\n    state.sector_resolved_enriched_deterministic += 1\n    state.qualified[\"Sector\"] = state.qualified.get(\"Sector\", 0) + 1\n'''
replace_once("cyberwatch/ai.py", old_fn, new_fn)

replace_once(
    "cyberwatch/normalize.py",
    '(config.LOC_REUNION, ["974", "saint denis de la reunion", "reunionnais", "reunionnaise"]),\n    (config.LOC_MAYOTTE, ["mayotte", "976", "mamoudzou", "mahorais", "mahoraise"]),',
    '(config.LOC_REUNION, ["saint denis de la reunion", "reunionnais", "reunionnaise"]),\n    (config.LOC_MAYOTTE, ["mayotte", "mamoudzou", "mahorais", "mahoraise"]),',
)
replace_once(
    "cyberwatch/normalize.py",
    '_REUNION_PROPER_NAME_RE = re.compile(r"\\b(?:La R[ée]union|LA R[ÉE]UNION)\\b")\n',
    '_REUNION_PROPER_NAME_RE = re.compile(r"\\b(?:La R[ée]union|LA R[ÉE]UNION)\\b")\n_REUNION_POSTAL_RE = re.compile(r"\\b974\\d{2}\\b")\n_MAYOTTE_POSTAL_RE = re.compile(r"\\b976\\d{2}\\b")\n_REUNION_DEPARTMENT_RE = re.compile(r"\\bdepartement\\s+(?:de\\s+)?974\\b")\n_MAYOTTE_DEPARTMENT_RE = re.compile(r"\\bdepartement\\s+(?:de\\s+)?976\\b")\n',
)
replace_once(
    "cyberwatch/normalize.py",
    '    blob = searchable(raw)\n    for location, hints in LOCATION_HINTS:\n',
    '    blob = searchable(raw)\n    if _REUNION_POSTAL_RE.search(blob) or _REUNION_DEPARTMENT_RE.search(blob):\n        return config.LOC_REUNION\n    if _MAYOTTE_POSTAL_RE.search(blob) or _MAYOTTE_DEPARTMENT_RE.search(blob):\n        return config.LOC_MAYOTTE\n    for location, hints in LOCATION_HINTS:\n',
)

tests = Path("tests/test_location_resolution.py")
text = tests.read_text(encoding="utf-8")
addition = r'''


def test_bare_974_976_are_not_geographic_evidence():
    assert classify_location("974 dossiers compromis") == config.LOC_INCONNU
    assert classify_location("976 comptes exposés") == config.LOC_INCONNU


def test_postal_codes_and_department_context_are_geographic_evidence():
    assert classify_location("Victime située au 97400 Saint-Denis") == config.LOC_REUNION
    assert classify_location("Entreprise du département 974") == config.LOC_REUNION
    assert classify_location("Victime située au 97600 Mamoudzou") == config.LOC_MAYOTTE
    assert classify_location("Entreprise du département 976") == config.LOC_MAYOTTE


def test_org_enrichment_can_resolve_location_when_sector_is_already_known(monkeypatch):
    item = _item("CYBERATTAQUE_ORG", "Cyberattaque confirmée", org="Org Location Seule")
    item.Sector = config.SECTOR_TECH
    calls = []

    def fake_resolve(org_key, organisation_raw, fetched_at, state):
        calls.append((org_key, organisation_raw))
        return org_enrichment.OrgEnrichmentRecord(
            Organisation_Key=org_key,
            Query_Name=organisation_raw,
            Matched_Name=organisation_raw,
            Match_Status=org_enrichment.MATCHED,
            Headquarters_Department="974",
            Fetched_At=fetched_at,
        )

    monkeypatch.setattr(org_enrichment, "resolve", fake_resolve)
    state = ai.AiRunState(enabled=False, org_enrichment=org_enrichment.OrgEnrichmentState(enabled=True))
    spec = sources.by_id("CYBERATTAQUE_ORG")
    assert spec is not None
    entry = RawEntry(title=item.Title, published=item.Published_Date, summary="Incident confirmé.", url=item.URL)
    ai.qualify_item(item, entry, spec, state)
    assert len(calls) == 1
    assert item.Sector == config.SECTOR_TECH
    assert item.Location == config.LOC_REUNION


def test_one_org_enrichment_resolves_sector_and_location_together(monkeypatch):
    item = _item("CYBERATTAQUE_ORG", "Cyberattaque confirmée", org="Org Double Enrichissement")
    calls = []

    def fake_resolve(org_key, organisation_raw, fetched_at, state):
        calls.append((org_key, organisation_raw))
        return org_enrichment.OrgEnrichmentRecord(
            Organisation_Key=org_key,
            Query_Name=organisation_raw,
            Matched_Name=organisation_raw,
            Match_Status=org_enrichment.MATCHED,
            Activity_Label="Information et communication",
            Headquarters_Department="976",
            Fetched_At=fetched_at,
        )

    monkeypatch.setattr(org_enrichment, "resolve", fake_resolve)
    state = ai.AiRunState(enabled=False, org_enrichment=org_enrichment.OrgEnrichmentState(enabled=True))
    spec = sources.by_id("CYBERATTAQUE_ORG")
    assert spec is not None
    entry = RawEntry(title=item.Title, published=item.Published_Date, summary="Incident confirmé.", url=item.URL)
    ai.qualify_item(item, entry, spec, state)
    assert len(calls) == 1
    assert item.Sector == config.SECTOR_TECH
    assert item.Location == config.LOC_MAYOTTE


def test_org_enrichment_never_overwrites_known_location(monkeypatch):
    item = _item(
        "CYBERATTAQUE_ORG", "Cyberattaque confirmée", org="Org Location Connue", location=config.LOC_REUNION
    )

    def fake_resolve(org_key, organisation_raw, fetched_at, state):
        return org_enrichment.OrgEnrichmentRecord(
            Organisation_Key=org_key,
            Query_Name=organisation_raw,
            Matched_Name=organisation_raw,
            Match_Status=org_enrichment.MATCHED,
            Activity_Label="Information et communication",
            Headquarters_Department="75",
            Fetched_At=fetched_at,
        )

    monkeypatch.setattr(org_enrichment, "resolve", fake_resolve)
    state = ai.AiRunState(enabled=False, org_enrichment=org_enrichment.OrgEnrichmentState(enabled=True))
    spec = sources.by_id("CYBERATTAQUE_ORG")
    assert spec is not None
    entry = RawEntry(title=item.Title, published=item.Published_Date, summary="Incident confirmé.", url=item.URL)
    ai.qualify_item(item, entry, spec, state)
    assert item.Sector == config.SECTOR_TECH
    assert item.Location == config.LOC_REUNION
'''
if "test_org_enrichment_can_resolve_location_when_sector_is_already_known" in text:
    raise SystemExit("tests déjà présents")
tests.write_text(text + addition, encoding="utf-8")

replace_once(
    "METHODOLOGY.md",
    "**Pipeline** (révisé — §Sector fiabilité, voir note de révision en fin de\nsection), déclenché uniquement quand `Sector` est encore `Inconnu` après les\nrègles déterministes et le backfill (§11 inchangé). L'enrichissement gratuit\net déterministe passe désormais **avant** tout appel LLM — un LLM ne doit\nêtre qu'un dernier recours, jamais l'étape automatique :",
    "**Pipeline** (révisé — §Sector fiabilité, voir note de révision en fin de\nsection) : l'enrichissement organisation est déclenché quand `Sector` **ou**\n`Location` est encore `Inconnu` après les règles déterministes et le backfill.\nUn unique match exact peut alimenter les deux champs : section NAF pour Sector,\ndépartement du siège pour Location. L'enrichissement gratuit et déterministe\npasse **avant** tout appel LLM — un LLM ne doit être qu'un dernier recours :",
)
