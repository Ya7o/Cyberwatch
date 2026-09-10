"""Réception de la chaîne de qualification — fixtures figées de l'audit du 10/09/2026.

Les textes viennent de `tests/fixtures/tampon_20260910/`, reconstitués par
l'audit `RUN-20260910T072351`. Ils ne sont jamais rechargés depuis les sites :
une régression doit rester reproductible même si l'article change.

Chaque test porte une ligne du tableau de réception : article capturé →
extraction → validation → faits conservés → décision → publication.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberwatch import (
    article_body,
    config,
    dedup,
    dedup_ai,
    dedup_ai_validation,
    duplicate_audit,
    enrichment,
    org_identity,
    source_facts,
    sources,
    threat_reservation,
)
from cyberwatch.collectors.base import RawEntry
from cyberwatch.identity import item_id
from cyberwatch.model import Item
from cyberwatch.normalize import organisation_key
from cyberwatch.org_identity import effective_organisation_key
from cyberwatch.sector import classify_sector_name

FIXTURES = Path(__file__).parent / "fixtures" / "tampon_20260910"
AUDIT = Path(__file__).resolve().parents[1] / "audit" / "latest_collection_2026-09-10"

FRENCHBREACHES_URL = "https://frenchbreaches.com/alertes/ville-du-tampon-mtu8oc7tsqxl3kzgkvm"
CYBERATTAQUE_URL = (
    "https://www.cyberattaque.org/le-tampon-une-cyberattaque-frappe-la-mairie-"
    "et-perturbe-fortement-les-services-municipaux/"
)


def _text(name: str) -> str:
    return (FIXTURES / f"{name}-context.txt").read_text(encoding="utf-8")


def _entry(url: str, organisation: str, text: str) -> RawEntry:
    title, _, body = text.partition("\n\n")
    return RawEntry(
        source_item_id=url,
        title=title.strip(),
        summary="",
        content=body.strip(),
        url=url,
        organisation=organisation,
        published="2026-09-09",
    )


def _item(source: str, organisation: str, url: str, threat: str, title: str) -> Item:
    key = organisation_key(organisation)
    return Item(
        Item_ID=item_id(source, "2026-09-09", key, url, url),
        Source_ID=source,
        Source_Item_ID=url,
        Published_Date="2026-09-09",
        Organisation_Raw=organisation,
        Organisation_Key=key,
        Threat_Raw=threat,
        Threat=threat,
        Sector=config.SECTOR_UNKNOWN,
        Location="La Réunion",
        Title=title,
        URL=url,
        Collected_As_Of="2026-09-10T07:23:51+04:00",
    )


@pytest.fixture
def identite_validee(monkeypatch):
    """Rejoue l'état d'après la décision du filet, sans refaire l'appel.

    Le registre versionné n'accepte que des décisions produites par la chaîne
    (`Origin=LLM_CONFIRMED`) : les tests dont le sujet n'est pas l'identité
    partent donc de la décision déjà validée, sans qu'aucune ligne saisie à la
    main n'existe dans `data/`.
    """
    monkeypatch.setattr(
        org_identity, "ORGANISATION_IDENTITY_REGISTRY", {"ville du tampon": "le tampon"},
    )


@pytest.fixture
def observations(monkeypatch):
    """Les deux observations du Tampon, extraites sans aucun appel LLM.

    `SOURCE_FACTS_AI_ENABLED=0` reproduit exactement le run audité : le filet
    sémantique est hors service et seules les règles déterministes travaillent.
    """
    from cyberwatch import source_facts_ai

    monkeypatch.setenv("SOURCE_FACTS_AI_ENABLED", "0")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    source_facts_ai.reset_runtime_for_tests()

    built: list[tuple[Item, RawEntry, dict]] = []
    for source, url, organisation, threat, name, title in (
        ("FRENCHBREACHES", FRENCHBREACHES_URL, "Ville du Tampon", "Fuite de données",
         "ITM-0c085da888611a12", "Ville du Tampon"),
        ("CYBERATTAQUE_ORG", CYBERATTAQUE_URL, "Le Tampon", "",
         "ITM-f2c9b54af4eae1da",
         "Le Tampon : une cyberattaque frappe la mairie et perturbe fortement les services municipaux"),
    ):
        entry = _entry(url, organisation, _text(name))
        item = _item(source, organisation, url, threat, title)
        spec = sources.by_id(source)
        fact = source_facts.extract_source_fact(item, entry, spec)
        built.append((item, entry, fact or {}))
    yield built
    source_facts_ai.reset_runtime_for_tests()


def _finalize(observations):
    items = [item for item, _, _ in observations]
    facts = [fact for _, _, fact in observations if fact]
    return enrichment.finalize_snapshot(
        items, facts, run_id="RUN-TEST-TAMPON", as_of="2026-09-10T07:23:51+04:00"
    )


# --- Menace, vecteur et niveau de preuve ------------------------------------

def test_premature_de_parler_de_ransomware_n_affirme_aucun_ransomware(observations):
    """Ligne 1 : la phrase de réserve ne doit produire aucune menace spécifique."""
    incidents = _finalize(observations).incidents
    assert {incident.Menace for incident in incidents} == {config.THREAT_UNKNOWN}


def test_cyberattaque_confirmee_conserve_l_incident_sans_vecteur(observations):
    """Ligne 2 : l'incident existe, mais aucun vecteur d'accès n'est publié."""
    result = _finalize(observations)
    assert result.incidents, "la cyberattaque confirmée doit rester un incident"
    for _, _, fact in observations:
        assert not fact.get("Initial_Access", ""), fact.get("Item_ID")


def test_l_explication_generale_n_attribue_aucune_exploitation(observations):
    """Ligne 3 : « la compromission d'un compte, l'exploitation d'une
    vulnérabilité ou l'infection d'un serveur peut conduire… » est pédagogique.
    """
    from cyberwatch.source_facts_ai_deterministic import _deterministic_initial_access

    body = article_body.body(_text("ITM-f2c9b54af4eae1da"))
    assert "exploitation d’une vulnérabilité" in body, "la phrase doit rester dans le corps"
    assert _deterministic_initial_access(body) is None


def test_le_defaut_frenchbreaches_ne_survit_pas_a_la_reserve(observations):
    """Ligne 4 : « Fuite de données » du flux ne doit pas atteindre la publication."""
    result = _finalize(observations)
    assert config.THREAT_LEAK not in {incident.Menace for incident in result.incidents}
    assert config.THREAT_LEAK not in {item.Threat for item in result.items}


def test_la_reserve_est_portee_par_les_metadonnees_source_facts(observations):
    """La décision voyage dans les métadonnées existantes, pas dans une table à part."""
    reservations = threat_reservation.index_source_facts(
        [fact for _, _, fact in observations if fact]
    )
    assert reservations, "au moins une observation doit porter une réserve archivée"
    for payload in reservations.values():
        assert payload["value"] == config.THREAT_UNKNOWN
        assert payload["evidence"]


# --- Secteur, localisation et identité --------------------------------------

def test_ville_du_tampon_est_une_collectivite_de_la_reunion(observations):
    """Ligne 5 : le préfixe « ville du » manquait aux règles sectorielles sûres."""
    assert classify_sector_name("Ville du Tampon") == config.SECTOR_ADMIN
    assert classify_sector_name("Commune du Tampon") == config.SECTOR_ADMIN
    result = _finalize(observations)
    for incident in result.incidents:
        assert incident.Secteur == config.SECTOR_ADMIN
        assert incident.Localisation == "La Réunion"


def test_sans_decision_validee_les_deux_libelles_restent_deux_incidents(observations):
    """Le déterministe ne devine pas une identité : il la laisse ouverte.

    C'est la situation d'avant décision. Elle n'est pas un défaut : rapprocher
    « Ville du X » de « X » sur la seule forme du libellé fusionnerait aussi
    une commune avec l'entreprise homonyme.
    """
    result = _finalize(observations)
    assert len(result.incidents) == 2


def test_le_filet_quotidien_voit_la_paire_que_le_deterministe_a_laissee(observations):
    """Ligne 6 : le mécanisme générique est armé sur ce cas, sans le nommer.

    Le filet ne reçoit que les paires non tranchées par le déterministe : une
    identité écrite à la main les lui cacherait, et le cas suivant, inconnu,
    ne serait pas couvert.
    """
    items = [item for item, _, _ in observations]
    candidats = duplicate_audit.find_daily_llm_candidates(items, items)
    paires = {
        frozenset((c.left.Organisation_Raw, c.right.Organisation_Raw)) for c in candidats
    }
    assert frozenset(("Ville du Tampon", "Le Tampon")) in paires


def test_une_decision_sourcee_produit_une_identite_machine(observations):
    """La décision passe la porte de validation et devient une ligne du registre."""
    items = [item for item, _, _ in observations]
    candidat = next(
        c for c in duplicate_audit.find_daily_llm_candidates(items, items)
        if {c.left.Organisation_Raw, c.right.Organisation_Raw}
        == {"Ville du Tampon", "Le Tampon"}
    )
    decision = dedup_ai.DedupAiDecision(
        status=dedup_ai.STATUS_OK, same_organisation=dedup_ai.SAME, confidence=0.95,
        evidence="La Ville du Tampon et Le Tampon désignent la même commune : "
                 "les deux articles décrivent la cyberattaque du 9 septembre 2026.",
    )
    row = dedup_ai_validation.validate_ai_dedup_decision(
        candidat, decision, model="gpt-5-nano", input_hash="h" * 64,
    )
    assert row is not None
    assert row["Origin"] == "LLM_CONFIRMED"
    assert {row["Alias_Key"], row["Canonical_Key"]} == {"le tampon", "ville du tampon"}
    assert row["Evidence"] and row["Input_Hash"]


def test_une_identite_validee_fait_une_fiche_a_deux_sources(observations, identite_validee):
    """Une fois la décision persistée, la fusion est déterministe et reproductible."""
    result = _finalize(observations)
    assert len(result.incidents) == 1
    incident = result.incidents[0]
    assert incident.Items_Count == 2
    assert set(str(incident.Sources).split(" | ")) == {"FRENCHBREACHES", "CYBERATTAQUE_ORG"}
    # Libellé publié : celui que les sources emploient le plus, départage stable.
    assert incident.Organisation == "Le Tampon"


def test_le_prefixe_administratif_n_est_jamais_generalise():
    """Généraliser aurait fusionné toute « Ville de X » avec l'entité « X »."""
    assert organisation_key("Ville du Tampon") != organisation_key("Le Tampon")
    assert effective_organisation_key("Ville de Paris") != effective_organisation_key("Paris")
    assert effective_organisation_key("Mairie de Bordeaux") != effective_organisation_key("Bordeaux")


def test_tarnos_reste_separe_du_tampon(observations, make_item, identite_validee):
    """Ligne 7 : le candidat Tarnos est du bruit de similarité de noms."""
    items = [item for item, _, _ in observations]
    tarnos = make_item(
        source="FRENCHBREACHES", org="Tarnos", url="https://frenchbreaches.com/alertes/tarnos",
        published="2026-08-29", threat=config.THREAT_UNKNOWN, sector=config.SECTOR_ADMIN,
        location="France métropolitaine", title="Tarnos",
    )
    incidents = dedup.build_incidents(items + [tarnos])
    organisations = {incident.Organisation for incident in incidents}
    assert "Tarnos" in organisations
    assert len(incidents) == 2


def test_les_gardes_fous_de_separation_restent_actifs(observations, make_item, identite_validee):
    """Ligne 8 : dates contradictoires et récidive séparent toujours."""
    items = [item for item, _, _ in observations]
    recidive = make_item(
        source="CYBERATTAQUE_ORG", org="Le Tampon", url="https://www.cyberattaque.org/le-tampon-2/",
        published="2026-11-30", threat=config.THREAT_UNKNOWN, sector=config.SECTOR_ADMIN,
        location="La Réunion", title="Le Tampon : nouvelle cyberattaque",
    )
    incidents = dedup.build_incidents(items + [recidive])
    assert len(incidents) == 2, "un événement distant de plusieurs mois reste un autre incident"


def test_82600_habitants_ne_devient_pas_un_nombre_de_victimes(observations):
    """Ligne 9 : une donnée de cadrage encyclopédique n'est pas un décompte."""
    for _, _, fact in observations:
        assert not fact.get("Affected_Count", "")
        assert not fact.get("Affected_Count_Raw", "")


# --- Entrées LLM, cache et traçabilité --------------------------------------

def test_l_article_connexe_et_le_pied_de_page_sont_isoles():
    """Ligne 12 : le corps principal est isolé et la réduction est tracée."""
    citadium = AUDIT / "ITM-3a1f12b53d6e809e-context.txt"
    if not citadium.exists():
        pytest.skip("preuves d'audit absentes de l'arbre")
    prepared = article_body.prepare(citadium.read_text(encoding="utf-8"))
    assert article_body.RELATED_ARTICLE in prepared.removed_codes
    assert article_body.FOOTER_RESOURCES in prepared.removed_codes
    # L'article connexe Shipup parlait d'autres victimes et d'une CVE.
    assert "Micromania" not in prepared.prepared
    assert "CVE-2026-72898" not in prepared.prepared
    # Le corps réel de Citadium survit entier.
    assert "Citadium également concerné par l’incident Shipup" in prepared.prepared
    # Et la préparation est documentée par ses empreintes et tailles.
    metadata = prepared.metadata()
    assert metadata["captured_chars"] > metadata["prepared_chars"] > 0
    assert metadata["captured_hash"] != metadata["prepared_hash"]
    assert [entry["code"] for entry in metadata["removed"]]


def test_le_pied_de_page_ne_qualifie_plus_la_menace():
    """Le seul « fuite de données » de l'article du Tampon était en pied de page."""
    from cyberwatch.normalize import classify_threat

    captured = _text("ITM-0c085da888611a12")
    assert "Annuaire fuite de données" in captured
    assert classify_threat(article_body.body(captured)) == config.THREAT_UNKNOWN


def test_la_reduction_du_dedoublonnage_garde_des_paragraphes_entiers():
    """Une réduction retire des paragraphes, jamais le milieu d'une phrase."""
    from cyberwatch import dedup_ai_evidence

    text = _text("ITM-0c085da888611a12")
    selected, reduction = dedup_ai_evidence.select(text, "Ville du Tampon", 900)
    assert reduction == "PARAGRAPH_SELECTION"
    assert len(selected) <= 900
    body = article_body.body(text)
    for block in selected.split("\n\n"):
        assert " ".join(block.split()) in " ".join(body.split())


def test_le_dedoublonnage_recoit_secteur_localisation_et_reserve(observations):
    """Le filet recevait titres et dates seuls : il reçoit désormais les preuves."""
    from cyberwatch import dedup_ai

    facts_by_item = {str(fact.get("Item_ID")): fact for _, _, fact in observations if fact}
    item = observations[1][0]
    payload = dedup_ai._item_payload(item, facts_by_item, "")
    assert payload["Location"] == "La Réunion"
    assert payload["Editorial_Evidence"], "le corps nettoyé doit être transmis"
    assert payload["Threat_Reservation"]["value"] == config.THREAT_UNKNOWN
    assert payload["Threat_Reservation"]["evidence"]


def test_une_paire_trop_volumineuse_est_differee_et_non_tronquee():
    """Ligne : le JSON d'une paire n'est jamais coupé au milieu."""
    from types import SimpleNamespace

    from cyberwatch import dedup_ai

    candidates = [
        SimpleNamespace(left=SimpleNamespace(Item_ID=f"ITM-{index}"),
                        right=SimpleNamespace(Item_ID=f"ITM-{index}b"))
        for index in range(2)
    ]
    entries = [
        (candidate, {"candidate_id": f"pair-{index}", "blob": "x" * 5000}, f"hash-{index}")
        for index, candidate in enumerate(candidates)
    ]
    state = SimpleNamespace(
        max_context_chars=1000, daily_max_candidates=10,
        candidates_not_reviewed_capacity=0, candidates_not_reviewed_too_large=0,
        candidates_selected=0,
    )
    results: dict = {}
    selected = dedup_ai._select_batch_entries(entries, state, results)
    assert selected == []
    assert state.candidates_not_reviewed_too_large == 2
    assert all(
        decision.status == dedup_ai.STATUS_NOT_REVIEWED_PAIR_TOO_LARGE
        for decision in results.values()
    )


def test_une_valeur_invalidee_reste_lisible_et_ne_revient_pas(monkeypatch, tmp_path):
    """Ligne 10 : le rejet est traçable ; la valeur n'est pas rematérialisée."""
    from cyberwatch import source_facts_ai
    from cyberwatch.source_facts_ai_contract import FIELD_VERSIONS

    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    source_facts_ai.reset_runtime_for_tests()
    runtime = source_facts_ai._runtime()
    runtime.cache["k"] = {"fields": {"impact": {
        "version": "version-obsolete",
        "status": "accepted",
        "misses": 0,
        "value": {"value": "des attaques ciblées possibles via des e-mails ou appels frauduleux.",
                  "confidence": 0.7, "evidence": "…"},
    }}}
    values, satisfied = source_facts_ai._read_field_cache(runtime, "k", {"impact"}, "contexte")
    assert values == {} and satisfied == set()
    record = runtime.cache["k"]["fields"]["impact"]
    assert record["status"] == source_facts_ai.CACHE_STATUS_INVALIDATED
    assert record["invalidated_reason"] == "CONTRACT_VERSION_CHANGED"
    assert record["invalidated_value"]["value"].startswith("des attaques ciblées possibles")
    assert record["value"] is None
    assert record["version"] == FIELD_VERSIONS["impact"]

    # Une seconde lecture ne la ressuscite pas et conserve son motif.
    values, satisfied = source_facts_ai._read_field_cache(runtime, "k", {"impact"}, "contexte")
    assert values == {} and satisfied == set()
    assert runtime.cache["k"]["fields"]["impact"]["status"] == (
        source_facts_ai.CACHE_STATUS_INVALIDATED
    )
    source_facts_ai.reset_runtime_for_tests()


def test_une_panne_llm_conserve_le_fait_valide_deja_extrait(monkeypatch, tmp_path):
    """Ligne 11 : une panne technique n'efface pas un fait valide ni n'invente d'abstention."""
    from cyberwatch import source_facts_ai
    from cyberwatch.source_facts_ai_contract import FIELD_VERSIONS

    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    source_facts_ai.reset_runtime_for_tests()
    runtime = source_facts_ai._runtime()
    runtime.cache["k"] = {"fields": {
        "third_party": {"version": FIELD_VERSIONS["third_party"], "status": "accepted",
                        "misses": 0, "value": {"value": "Shipup", "confidence": 1.0,
                                               "evidence": "prestataire Shipup"}},
        "impact": {"version": FIELD_VERSIONS["impact"], "status": "miss", "misses": 1,
                   "value": None},
    }}
    values, satisfied = source_facts_ai._read_field_cache(
        runtime, "k", {"third_party", "impact"}, "prestataire Shipup"
    )
    assert values["third_party"]["value"] == "Shipup"
    assert satisfied == {"third_party"}
    # Le champ en panne reste `miss` : ni abstention, ni effacement.
    assert runtime.cache["k"]["fields"]["impact"]["status"] == "miss"
    source_facts_ai.reset_runtime_for_tests()


# --- Verdict de qualification -----------------------------------------------

def test_le_verdict_distingue_desactivation_et_absence_de_besoin(tmp_path):
    """Une clé absente couverte par le cache n'est pas un échec ; un besoin non
    servi en est un."""
    from cyberwatch import qualification

    def run(**extraction):
        return qualification.QualificationRun(
            run_id="RUN-TEST", extraction=extraction, documented=True
        )

    covered = qualification.evaluate(run(
        items_eligible=6, items_would_call=0, calls_attempted=0,
        disabled_reason="API_KEY_MISSING", accepted_field_cache_hits=17,
    ))
    assert covered["state"] == qualification.STATE_NOT_NEEDED
    assert covered["reasons"] == []

    starved = qualification.evaluate(run(
        items_eligible=6, items_would_call=4, calls_attempted=0,
        disabled_reason="API_KEY_MISSING",
    ))
    assert starved["state"] == qualification.STATE_PARTIAL
    assert any("API_KEY_MISSING" in reason for reason in starved["reasons"])

    unknown = qualification.evaluate(
        qualification.QualificationRun(run_id="RUN-ANCIEN", documented=False)
    )
    assert unknown["state"] == qualification.STATE_UNKNOWN


def test_le_modele_execute_reste_vide_sans_appel():
    """Modèle demandé, modèle résolu et modèle déclaré sont trois choses."""
    from cyberwatch import qualification

    verdict = qualification.evaluate(qualification.QualificationRun(
        run_id="RUN-TEST", documented=True,
        extraction={"requested_model": "gpt-5-nano", "effective_model": "",
                    "items_would_call": 0},
    ))
    assert verdict["extraction"]["requested_model"] == "gpt-5-nano"
    assert verdict["extraction"]["effective_model"] == ""


def test_le_rapport_rend_les_deux_tableaux():
    """`report --qualification` doit produire extraction ET déduplication."""
    from cyberwatch import qualification

    run = qualification.QualificationRun(
        run_id="RUN-TEST", documented=True,
        extraction={"items_would_call": 1, "calls_attempted": 1},
        trace=[{
            "item_id": "ITM-1", "url": "https://example.org/a", "status": "cache_read",
            "requested_fields": ["impact"],
            "fields": {"impact": {"status": "accepted", "value": {
                "value": "Perturbations", "evidence": "les services sont perturbés"}}},
        }],
        dedup={"summary": {"dedup_candidates_generated": 1},
               "pairs": [{"pair_key": "A|B", "left": "A", "right": "B", "status": "APPLIED",
                          "same_organisation": "SAME", "same_incident": "SAME",
                          "confidence": 0.95, "model": "gpt-4o-mini"}]},
    )
    report = qualification.markdown_report(run)
    assert "### Extraction → décision par champ" in report
    assert "### Déduplication par paire" in report
    assert "| ITM-1 | impact | cache |" in report
    assert "A ↔ B" in report
    assert json.loads(json.dumps(qualification.evaluate(run)))["state"] == (
        qualification.STATE_COMPLETE
    )


# --- Évaluation isolée du modèle courant ------------------------------------

def test_l_evaluation_n_appelle_rien_et_declare_sa_couverture(tmp_path, monkeypatch, identite_validee):
    """L'évaluation tourne hors réseau, hors production, et le dit."""
    import importlib.util

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("SOURCE_FACTS_AI_ENABLED", "0")
    script = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_qualification.py"
    spec = importlib.util.spec_from_file_location("evaluate_qualification", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    from cyberwatch import store

    before = (store.ITEMS_CSV.read_bytes(), store.INCIDENTS_CSV.read_bytes(),
              store.SOURCE_FACTS_CSV.read_bytes())
    out = tmp_path / "eval.json"
    assert module.main(["--out", str(out)]) == 0
    assert (store.ITEMS_CSV.read_bytes(), store.INCIDENTS_CSV.read_bytes(),
            store.SOURCE_FACTS_CSV.read_bytes()) == before

    result = json.loads(out.read_text(encoding="utf-8"))
    # Sans appel, l'étage « réponse brute » n'est pas mesuré et ne peut pas
    # fonder une conclusion sur le modèle.
    assert result["verdict"]["label"] == module.NOT_MEASURED
    assert result["verdict"]["raw_stage_measured"] is False
    assert result["verdict"]["complete"] is False
    assert "aucune supériorité" in result["verdict"]["model_comparison"]
    # Les étages validation et publication, eux, sont mesurables hors réseau.
    assert result["validated"]["measured"] is True
    assert result["published"]["measured"] is True
    assert result["published"]["incorrect_published_fields"] == []
    assert result["published"]["correct_merges"] == 2
    assert result["published"]["false_merges"] == []
    for row in result["validated"]["articles"]:
        assert row["missing_abstentions"] == []
        assert row["unsupported_claims"] == []
        assert row["quoted_evidence_grounded"] is True


def test_l_evaluation_reste_partielle_si_l_api_est_demandee_sans_cle(tmp_path, monkeypatch, capsys):
    """`--api` sans clé ne bascule pas silencieusement en mode mesuré."""
    import importlib.util

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    script = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_qualification.py"
    spec = importlib.util.spec_from_file_location("evaluate_qualification", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    out = tmp_path / "eval.json"
    assert module.main(["--api", "--out", str(out)]) == 0
    assert "OPENAI_API_KEY absente" in capsys.readouterr().err
    assert json.loads(out.read_text(encoding="utf-8"))["verdict"]["label"] == module.NOT_MEASURED


def test_le_verdict_atteint_le_payload_de_statut():
    """Le dashboard reçoit l'objet `qualification`, pas seulement les journaux."""
    from cyberwatch import qualification, site_status

    payload = site_status.build({}, lambda rows, metadata: {})
    assert "qualification" in payload
    verdict = payload["qualification"]
    assert set(verdict) == {"run_id", "state", "reasons", "pending_fields",
                            "pending_fields_available", "pending_pairs", "pairs", "label",
                            "sectors", "pending_required_fields"}
    # La couverture sectorielle publiée et l'état d'extraction sont deux
    # lectures distinctes : les couples ne se déduisent pas des secteurs.
    assert verdict["pairs"] is None or "requested" in verdict["pairs"]
    assert verdict["state"] in {
        qualification.STATE_COMPLETE, qualification.STATE_PARTIAL,
        qualification.STATE_NOT_NEEDED, qualification.STATE_UNKNOWN,
    }
    # « Qualification incomplète » n'est affiché que sur un verdict PARTIAL.
    assert bool(verdict["label"]) == (verdict["state"] == qualification.STATE_PARTIAL)


def test_l_alerte_de_production_porte_la_qualification_incomplete(monkeypatch):
    """Le mécanisme d'alerte existant reçoit le motif, sans nouveau canal."""
    from cyberwatch import production, qualification

    monkeypatch.setattr(qualification, "payload", lambda *_args, **_kwargs: {
        "run_id": "RUN-TEST", "state": qualification.STATE_PARTIAL,
        "reasons": ["2 champ(s) d'extraction différé(s)"],
        "pending_fields": 2, "pending_pairs": 0,
        "label": qualification.INCOMPLETE_LABEL,
    })
    payload = production.health_payload()
    assert payload["alert"] is True
    assert any(qualification.INCOMPLETE_LABEL in reason for reason in payload["alert_reasons"])
    assert payload["qualification"]["state"] == qualification.STATE_PARTIAL
    assert qualification.INCOMPLETE_LABEL in production.markdown_report(payload)
