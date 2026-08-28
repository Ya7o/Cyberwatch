"""Source facts LLM : préflight, grounding, cache par champ et garde-fous."""
from __future__ import annotations

import json

from cyberwatch import source_facts_ai as sfa
from cyberwatch.collectors.base import RawEntry
from cyberwatch.model import Item


def _item(source="CYBERATTAQUE_ORG"):
    return Item(
        Item_ID="ITM-ai", Source_ID=source, Organisation_Raw="Exemple SA",
        Published_Date="2026-08-16",
    )


def _payload(output: dict):
    return {
        "output_text": json.dumps(output, ensure_ascii=False),
        "usage": {"input_tokens": 100, "output_tokens": 50},
    }


def _output_for(body: dict, **values):
    result = {}
    properties = body["text"]["format"]["schema"]["properties"]
    for field in properties:
        if field in {"data_types", "affected_counts", "data_volumes", "file_counts", "attack_flow"}:
            result[field] = values.get(field, [])
        else:
            result[field] = values.get(
                field, {"value": "", "confidence": 0.0, "evidence": ""}
            )
    return result


def _configure(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    monkeypatch.setenv("SOURCE_FACTS_AI_STATS_PATH", str(tmp_path / "stats.json"))
    sfa.reset_runtime_for_tests()


def test_pas_de_cle_pas_dappel(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    sfa.reset_runtime_for_tests()
    called = []
    monkeypatch.setattr(sfa, "_post_openai", lambda *_: called.append(True))
    assert sfa.enrich(_item(), RawEntry(title="X", content="Incident")) is None
    assert not called


def test_types_de_donnees_deterministes_sans_api(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    sfa.reset_runtime_for_tests()
    entry = RawEntry(
        title="Exemple",
        content="Une fuite a exposé des adresses e-mail et des numéros de téléphone.",
    )
    result = sfa.enrich(_item(), entry)
    values = {fact["value"] for fact in result["data_types"]}
    assert "adresses e-mail" in values
    assert "numéros de téléphone" in values
    assert sfa.runtime_stats()["calls_attempted"] == 0


def test_headline_est_demandee_meme_sur_contenu_court(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    called = []
    monkeypatch.setattr(sfa, "_post_openai", lambda *_: called.append(True) or _payload({"summary": {"value": "LockBit revendique une attaque contre Exemple SA.", "confidence": .9, "evidence": "attaque a été revendiquée par LockBit"}}))
    entry = RawEntry(
        title="Exemple SA",
        content="L'attaque a été revendiquée par LockBit.",
    )
    assert sfa.fields_needed_for_ai(_item(), entry) == {"summary"}
    assert sfa.enrich(_item(), entry)["summary"]["value"].startswith("LockBit")
    assert called


def test_headline_technique_ou_generique_est_rejetee():
    context = "Géotec confirme une exfiltration de données."
    generic = {"value": "L'incident a entraîné une exfiltration de données.", "confidence": .9, "evidence": context}
    technical = {"value": "Géotec — grosse amélioration de la vitesse d'apparition visuelle.", "confidence": .9, "evidence": context}
    assert sfa._normalize_summary(generic, context) is None
    assert sfa._normalize_summary(technical, context) is None


def test_activity_description_llm_is_grounded_and_becomes_a_provisional_signal():
    context = (
        "Exemple SA, éditeur de logiciels de comptabilité pour les PME, "
        "a confirmé avoir subi une intrusion."
    )
    result = sfa._normalize({
        "activity_description": {
            "value": "éditeur de logiciels de comptabilité pour les PME",
            "confidence": 0.92,
            "evidence": "Exemple SA, éditeur de logiciels de comptabilité pour les PME",
        },
    }, context, {"activity_description"})
    assert result["activity_description"]["value"] == "éditeur de logiciels de comptabilité pour les PME"

    # Une activité sans citation de l'article n'est jamais conservée.
    assert sfa._normalize({
        "activity_description": {
            "value": "éditeur de logiciels",
            "confidence": 0.92,
            "evidence": "activité inventée",
        },
    }, context, {"activity_description"}) == {}


def test_schema_dynamique_acteur_uniquement_plus_resume(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    bodies = []

    def fake_post(body, _runtime):
        bodies.append(body)
        return _payload(_output_for(
            body,
            summary={
                "value": "L'attaque est attribuée à LockBit.",
                "confidence": .9,
                "evidence": "attaque a été attribuée à LockBit",
            },
            threat_actor={
                "value": "LockBit",
                "confidence": .95,
                "evidence": "attaque a été attribuée à LockBit",
            },
        ))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    result = sfa.enrich(
        _item(), RawEntry(title="Exemple", content="L'attaque a été attribuée à LockBit.")
    )
    assert len(bodies) == 1
    props = set(bodies[0]["text"]["format"]["schema"]["properties"])
    assert props == {"summary", "threat_actor"}
    assert result["threat_actor"]["value"] == "LockBit"


def test_enrichissement_80_20_extrait_vecteur_flow_resume_impact(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    bodies = []
    entry = RawEntry(
        title="Exemple SA",
        content=(
            "L'attaquant a exploité une vulnérabilité du portail VPN pour obtenir un accès initial. "
            "Il a ensuite accédé au serveur de fichiers puis exfiltré des données clients. "
            "La fuite concerne des informations personnelles de clients de l'entreprise."
        ),
    )

    def fake_post(body, _runtime):
        bodies.append(body)
        return _payload(_output_for(
            body,
            summary={
                "value": "Intrusion via une vulnérabilité VPN suivie d'une exfiltration de données clients.",
                "confidence": .96,
                "evidence": "L'attaquant a exploité une vulnérabilité du portail VPN pour obtenir un accès initial.",
            },
            initial_access={
                "value": "vulnerability_exploitation",
                "confidence": .99,
                "evidence": "L'attaquant a exploité une vulnérabilité du portail VPN pour obtenir un accès initial.",
            },
            attack_flow=[
                {
                    "action": "Exploitation d'une vulnérabilité VPN",
                    "confidence": .99,
                    "evidence": "L'attaquant a exploité une vulnérabilité du portail VPN pour obtenir un accès initial.",
                },
                {
                    "action": "Exfiltration de données clients",
                    "confidence": .97,
                    "evidence": "Il a ensuite accédé au serveur de fichiers puis exfiltré des données clients.",
                },
            ],
            impact={
                "value": "Des données clients ont été exfiltrées.",
                "confidence": .95,
                "evidence": "Il a ensuite accédé au serveur de fichiers puis exfiltré des données clients.",
            },
        ))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    result = sfa.enrich(_item(), entry)
    props = set(bodies[0]["text"]["format"]["schema"]["properties"])
    assert {"summary", "initial_access", "attack_flow", "impact"} <= props
    assert result["initial_access"]["value"] == "vulnerability_exploitation"
    assert len(result["attack_flow"]) == 2
    assert result["summary"]["value"].startswith("Intrusion via")
    assert result["impact"]["value"]


def test_vecteur_inconnu_ne_devient_jamais_une_hypothese(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    entry = RawEntry(
        title="Exemple SA",
        content=(
            "Le vecteur initial reste inconnu et n'a pas été communiqué. "
            "Il pourrait s'agir d'un phishing, d'identifiants compromis ou d'une vulnérabilité. "
            "L'organisation poursuit ses investigations sur l'incident."
        ),
    )

    def fake_post(body, _runtime):
        return _payload(_output_for(
            body,
            initial_access={
                "value": "phishing",
                "confidence": .95,
                "evidence": "Il pourrait s'agir d'un phishing",
            },
        ))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    result = sfa.enrich(_item(), entry) or {}
    assert "initial_access" not in result


def test_identifiants_exposes_ne_qualifient_pas_seuls_le_vecteur(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    entry = RawEntry(
        title="Sport 2000",
        content=(
            "Les données publiées contiennent des identifiants et des moyens de paiement. "
            "L'origine de l'intrusion n'est pas établie."
        ),
    )

    def fake_post(body, _runtime):
        return _payload(_output_for(
            body,
            initial_access={
                "value": "compromised_credentials",
                "confidence": .95,
                "evidence": "Les données publiées contiennent des identifiants",
            },
        ))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    result = sfa.enrich(_item(), entry) or {}
    assert "initial_access" not in result


def test_vecteur_conditionnel_impossible_a_determiner_est_inconnu():
    """Régression Sport 2000 : une alternative n'est pas un vecteur établi."""
    context = (
        "Il reste donc impossible de déterminer si l’accès provient "
        "d’identifiants compromis, d’une faiblesse d’authentification ou d’un autre mécanisme."
    )
    candidate = {
        "value": "compromised_credentials",
        "confidence": .99,
        "evidence": context,
    }

    assert sfa._deterministic_initial_access(context) is None
    assert sfa._normalize_initial_access(candidate, context) is None


def test_attack_flow_exclut_remediation_et_hypotheses(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    entry = RawEntry(
        title="Exemple",
        content=(
            "L'attaquant a exfiltré des données clients après son intrusion. "
            "L'entreprise a isolé les serveurs et lancé une investigation forensic. "
            "Un mouvement latéral pourrait avoir eu lieu mais cela n'est pas confirmé."
        ),
    )

    def fake_post(body, _runtime):
        return _payload(_output_for(
            body,
            attack_flow=[
                {
                    "action": "Exfiltration de données clients", "confidence": .95,
                    "evidence": "L'attaquant a exfiltré des données clients après son intrusion.",
                },
                {
                    "action": "Isolation des serveurs", "confidence": .99,
                    "evidence": "L'entreprise a isolé les serveurs et lancé une investigation forensic.",
                },
                {
                    "action": "Mouvement latéral", "confidence": .9,
                    "evidence": "Un mouvement latéral pourrait avoir eu lieu mais cela n'est pas confirmé.",
                },
            ],
        ))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    result = sfa.enrich(_item(), entry) or {}
    assert [step["action"] for step in result["attack_flow"]] == ["Exfiltration de données clients"]


def test_evidence_non_presente_est_rejetee(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)

    def fake_post(body, _runtime):
        return _payload(_output_for(
            body,
            threat_actor={
                "value": "LockBit", "confidence": .99, "evidence": "texte inventé absent"
            },
        ))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    result = sfa.enrich(
        _item(), RawEntry(title="Exemple", content="L'attaque est attribuée à LockBit.")
    ) or {}
    assert "threat_actor" not in result


def test_acteur_et_tiers_doivent_etre_nommes_dans_evidence(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)

    def fake_post(body, _runtime):
        return _payload(_output_for(
            body,
            threat_actor={"value": "LockBit", "confidence": .99, "evidence": "incident attribué"},
            third_party={"value": "Example Cloud", "confidence": .99, "evidence": "via le prestataire externe"},
        ))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    result = sfa.enrich(
        _item(),
        RawEntry(
            title="Exemple",
            content=(
                "Incident attribué à LockBit. La victime indique être hébergée via le "
                "prestataire externe Example Cloud, affecté par l'incident."
            ),
        ),
    ) or {}
    assert "threat_actor" not in result
    assert "third_party" not in result


def test_cache_par_champ_et_changement_contenu(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    calls = []

    def fake_post(body, _runtime):
        calls.append(1)
        actor = "LockBit" if "LockBit" in json.dumps(body) else "Qilin"
        evidence = f"attaque a été attribuée à {actor}"
        return _payload(_output_for(
            body,
            summary={"value": evidence, "confidence": .9, "evidence": evidence},
            threat_actor={"value": actor, "confidence": .9, "evidence": evidence},
        ))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    first = RawEntry(title="Exemple", content="L'attaque a été attribuée à LockBit.")
    second = RawEntry(title="Exemple", content="L'attaque a été attribuée à Qilin.")
    sfa.enrich(_item(), first)
    sfa.enrich(_item(), first)
    sfa.enrich(_item(), second)
    assert len(calls) == 2
    stats = sfa.runtime_stats()
    assert stats["cache_hits"] == 1
    assert stats["field_cache_hits"] >= 2
    sfa._flush_runtime()
    payload = json.loads((tmp_path / "cache.json").read_text(encoding="utf-8"))
    assert payload["_format"] == sfa.CACHE_FORMAT
    assert payload["entries"]
    assert (tmp_path / "stats.json").exists()


def test_invalidation_dun_champ_ne_recalcule_pas_les_autres(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    calls = []
    entry = RawEntry(
        title="Exemple",
        content=(
            "L'attaquant a exploité une vulnérabilité pour obtenir un accès initial. "
            "Il a ensuite exfiltré des données de l'entreprise après l'intrusion."
        ),
    )

    def fake_post(body, _runtime):
        calls.append(set(body["text"]["format"]["schema"]["properties"]))
        return _payload(_output_for(
            body,
            summary={"value": "Intrusion puis exfiltration.", "confidence": .9, "evidence": "Il a ensuite exfiltré des données de l'entreprise après l'intrusion."},
            initial_access={"value": "vulnerability_exploitation", "confidence": .95, "evidence": "L'attaquant a exploité une vulnérabilité pour obtenir un accès initial."},
            attack_flow=[{"action": "Exfiltration", "confidence": .95, "evidence": "Il a ensuite exfiltré des données de l'entreprise après l'intrusion."}],
            impact={"value": "Données exfiltrées", "confidence": .9, "evidence": "Il a ensuite exfiltré des données de l'entreprise après l'intrusion."},
        ))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    sfa.enrich(_item(), entry)
    monkeypatch.setitem(sfa.FIELD_VERSIONS, "initial_access", "initial-access-v2-test")
    sfa.enrich(_item(), entry)
    assert len(calls) == 2
    assert calls[1] == {"initial_access"}
    assert sfa.runtime_stats()["fields_invalidated"] >= 1


def test_ancien_cache_reutilise_les_champs_compatibles(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    item = _item()
    entry = RawEntry(title="Exemple", content="L'attaque a été attribuée à LockBit.")
    runtime = sfa._runtime()
    legacy_fields = {"summary", "threat_actor"}
    key = sfa._legacy_input_hash(item, entry, runtime, legacy_fields)
    runtime.legacy_cache[key] = {
        "summary": {"value": "Ancien résumé", "confidence": .9, "evidence": "attaque a été attribuée à LockBit"},
        "threat_actor": {"value": "LockBit", "confidence": .95, "evidence": "attaque a été attribuée à LockBit"},
    }
    bodies = []

    def fake_post(body, _runtime):
        bodies.append(body)
        return _payload(_output_for(
            body,
            summary={"value": "L'attaque est attribuée à LockBit.", "confidence": .9, "evidence": "attaque a été attribuée à LockBit"},
        ))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    result = sfa.enrich(item, entry)
    assert result["threat_actor"]["value"] == "LockBit"
    assert set(bodies[0]["text"]["format"]["schema"]["properties"]) == {"summary"}
    assert sfa.runtime_stats()["legacy_field_cache_hits"] == 1


def test_budget_appels_est_respecte(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    monkeypatch.setenv("SOURCE_FACTS_AI_MAX_CALLS_PER_RUN", "1")
    sfa.reset_runtime_for_tests()
    calls = []

    def fake_post(body, _runtime):
        calls.append(1)
        return _payload(_output_for(body))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    sfa.enrich(_item(), RawEntry(title="A", content="L'attaque a été attribuée à LockBit."))
    item2 = _item()
    item2.Item_ID = "ITM-ai-2"
    sfa.enrich(item2, RawEntry(title="B", content="L'attaque a été attribuée à Qilin."))
    assert len(calls) == 1
    assert sfa.runtime_stats()["calls_budget_blocked"] == 1


def test_autres_sources_jamais_envoyees_au_llm(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    called = []
    monkeypatch.setattr(sfa, "_post_openai", lambda *_: called.append(1))
    item = _item("BONJOURLAFUITE")
    assert sfa.enrich(item, RawEntry(title="X", content="Données")) is None
    assert not called


def test_alaxione_synthese_trop_longue_est_rejetee():
    """Cas de non-régression : la synthèse doit être une headline, pas un
    second récit de l'incident (point 1 du tableau de revue manuelle)."""
    long_summary = (
        "Alaxione a été victime d'une cyberattaque revendiquée par un groupe "
        "qui affirme avoir exfiltré plusieurs bases de données clients avant "
        "de les proposer à la vente sur un forum spécialisé, une opération "
        "qui rappelle plusieurs incidents similaires observés cette année."
    )
    assert len(long_summary) > sfa.MAX_HEADLINE_CHARS
    context = f"{long_summary} Extrait exact de l'article source."
    raw = {"summary": {"value": long_summary, "confidence": 0.9, "evidence": long_summary}}
    result = sfa._normalize(raw, context, {"summary"})
    assert "summary" not in result


def test_alaxione_headline_courte_est_acceptee():
    short_summary = "Alaxione confirme une fuite de données clients revendiquée par un groupe cybercriminel."
    assert len(short_summary) <= sfa.MAX_HEADLINE_CHARS
    context = f"{short_summary} Détails supplémentaires dans l'article."
    raw = {"summary": {"value": short_summary, "confidence": 0.9, "evidence": short_summary}}
    result = sfa._normalize(raw, context, {"summary"})
    assert result["summary"]["value"] == short_summary


def test_alaxione_data_type_narratif_est_rejete():
    """Cas de non-régression : un data_types est un libellé court, pas un
    extrait narratif accusatoire (point 1 du tableau de revue manuelle)."""
    long_value = (
        "Alaxione ment dans sa communication en soutenant qu'il s'agit d'un "
        "incident mineur alors que les données exfiltrées concernent des "
        "milliers de clients et de salariés."
    )
    assert len(long_value) > sfa.MAX_LABEL_VALUE_CHARS
    context = f"{long_value} Extrait exact de l'article source."
    raw = {"data_types": [{"value": long_value, "confidence": 0.9, "evidence": long_value}]}
    result = sfa._normalize(raw, context, {"data_types"})
    assert "data_types" not in result


def test_data_type_court_est_accepte():
    short_value = "adresses e-mail"
    context = f"Fuite de {short_value} confirmée. Extrait exact de l'article source."
    raw = {"data_types": [{"value": short_value, "confidence": 0.9, "evidence": "adresses e-mail"}]}
    result = sfa._normalize(raw, context, {"data_types"})
    assert result["data_types"][0]["value"] == short_value


def test_data_type_cited_only_in_a_denial_is_rejected():
    context = (
        "Les données exposées comprennent des noms et des adresses e-mail. "
        "Nous n'avons pas identifié de numéro complet de carte bancaire ni d'IBAN."
    )
    raw = {
        "data_types": [
            {"value": "IBAN / RIB", "confidence": 0.9, "evidence": "IBAN"},
            {"value": "cartes de paiement", "confidence": 0.9, "evidence": "carte bancaire"},
            {"value": "adresses e-mail", "confidence": 0.9, "evidence": "adresses e-mail"},
        ]
    }
    result = sfa._normalize(raw, context, {"data_types"})
    assert [row["value"] for row in result["data_types"]] == ["adresses e-mail"]


def test_deterministic_data_type_cited_only_in_a_denial_is_rejected():
    context = (
        "Les données exposées comprennent des noms et des adresses e-mail. "
        "Nous n'avons pas identifié de numéro complet de carte bancaire ni d'IBAN."
    )
    values = sfa._deterministic_data_types(context)
    assert [row["value"] for row in values] == ["adresses e-mail"]


def test_deterministic_data_types_rejette_une_negation_placee_apres_la_liste():
    context = (
        "Les données clients exposées comprennent le nom, l'adresse e-mail et le téléphone. "
        "Les informations bancaires, identifiants de connexion et mots de passe "
        "ne sont pas concernés par cette fuite."
    )

    assert [row["value"] for row in sfa._deterministic_data_types(context)] == [
        "adresses e-mail",
        "numéros de téléphone",
    ]


def test_deterministic_data_types_rejette_une_negation_placee_avant_la_liste():
    context = (
        "Les données exposées comprennent le nom, l'adresse e-mail et le téléphone. "
        "Pas de mots de passe ni de cartes bancaires concernés."
    )

    assert [row["value"] for row in sfa._deterministic_data_types(context)] == [
        "adresses e-mail",
        "numéros de téléphone",
    ]


def test_vulnerabilite_de_contexte_corrigee_n_est_pas_le_vecteur_de_l_incident():
    context = (
        "Des indices orientent vers une extraction via Metabase. "
        "Le contexte actuel est particulier : une vulnérabilité critique de "
        "Metabase permettant un accès administrateur a récemment été corrigée "
        "après avoir été exploitée comme zero-day."
    )

    assert sfa._deterministic_initial_access(context) is None


def test_impact_long_reste_accepte_car_hors_perimetre_du_plafond_data_types():
    """`impact` réutilise `_normalize_fact` mais n'est pas concerné par
    MAX_LABEL_VALUE_CHARS : une conséquence documentée peut légitimement
    dépasser 120 caractères (jusqu'à MAX_EVIDENCE_CHARS)."""
    long_impact = (
        "L'attaque a entraîné l'arrêt temporaire de plusieurs services internes "
        "et la mise en place d'une cellule de crise pour limiter la propagation."
    )
    assert len(long_impact) > sfa.MAX_LABEL_VALUE_CHARS
    context = f"{long_impact} Extrait exact de l'article source."
    raw = {"impact": {"value": long_impact, "confidence": 0.9, "evidence": long_impact}}
    result = sfa._normalize(raw, context, {"impact"})
    assert result["impact"]["value"] == long_impact


def test_impact_risque_prospectif_est_rejete():
    """Point 2 : « risque de », « expose à » et « augmente le risque » ne sont
    pas des conséquences observées."""
    context = "L'incident augmente le risque de fraude pour les clients concernés."
    raw = {"value": "augmente le risque de fraude", "confidence": 0.9, "evidence": context}
    assert sfa._normalize_impact(raw, context) is None

    context = "La fuite expose les utilisateurs à un risque d'usurpation d'identité."
    raw = {"value": "expose les utilisateurs à un risque d'usurpation d'identité", "confidence": 0.9, "evidence": context}
    assert sfa._normalize_impact(raw, context) is None


def test_impact_consequence_observee_est_acceptee():
    context = "La production a été interrompue pendant trois jours suite à l'attaque."
    raw = {"value": "production interrompue pendant trois jours", "confidence": 0.9, "evidence": context}
    assert sfa._normalize_impact(raw, context) is not None


def test_geotec_categorie_non_precisee_est_conservee():
    """Point 5 : un fait négatif explicite (exfiltration confirmée, catégories
    non communiquées) ne doit pas laisser une fiche vide indistincte d'une
    absence d'extraction."""
    context = (
        "Géotec confirme avoir été victime d'une exfiltration de données par un "
        "groupe de ransomware. Les catégories de données concernées n'ont pas "
        "été précisées par l'entreprise à ce stade."
    )
    result = sfa._deterministic_data_types(context)
    assert result == [{
        "value": sfa.DATA_TYPES_UNDISCLOSED_LABEL,
        "confidence": 1.0,
        "evidence": "catégories de données concernées n'ont pas été précisées",
    }]


def test_absence_de_toute_mention_reste_vide():
    """Pas de fuite/exfiltration mentionnée : aucune invention de fait négatif."""
    context = "Géotec annonce une mise à jour de son site internet."
    assert sfa._deterministic_data_types(context) == []


def test_normalisation_llm_rejette_le_nom_canonique_seul():
    context = "L'article décrit un incident chez Exemple SA."
    result = sfa._normalize(
        {"summary": {"value": "Exemple SA", "confidence": .9, "evidence": "Exemple SA"}},
        context,
        {"summary"},
        "Exemple SA",
    )
    assert result == {}


def test_force_full_refresh_reouvre_tous_les_champs_semantiques(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    item, entry = _item(), RawEntry(title="Exemple SA", content="Article éditorial complet.")
    runtime = sfa._runtime()
    key = sfa._cache_item_key(item, entry, runtime)
    runtime.cache[key] = {"fields": {
        "summary": {"version": sfa.FIELD_VERSIONS["summary"], "status": "accepted", "value": {"value": "Résumé utile", "evidence": "Article"}},
        "impact": {"version": sfa.FIELD_VERSIONS["impact"], "status": "accepted", "value": {"value": "Impact", "evidence": "Article"}},
    }}

    sfa.force_full_refresh(item, entry)
    assert runtime.force_field_keys[key] == set(sfa._LLM_FIELDS)


def test_article_riche_normalise_tous_les_faits_semantiques_et_les_revalide():
    context = (
        "L'attaque du 2026-08-12 a exploité CVE-2026-12345 sur le portail VPN. "
        "150 000 clients sont concernés, 2,4 To de données et 12 000 fichiers ont été exfiltrés. "
        "La base clients contient des noms et des e-mails. Les serveurs VMware ESXi ont été interrompus 48 h."
    )
    raw = {
        "attack_date": {"value": "2026-08-12", "confidence": .9, "evidence": "attaque du 2026-08-12"},
        "vulnerabilities": [{"value": "CVE-2026-12345", "confidence": .9, "evidence": "CVE-2026-12345"}],
        "affected_counts": [{"value": 150000, "unit": "clients", "scope": "total", "status": "confirmed", "confidence": .9, "evidence": "150 000 clients sont concernés"}],
        "data_volumes": [{"value": "2,4 To", "unit": "TB", "scope": "total", "status": "confirmed", "confidence": .9, "evidence": "2,4 To de données"}],
        "file_counts": [{"value": 12000, "unit": "files", "scope": "total", "status": "confirmed", "confidence": .9, "evidence": "12 000 fichiers ont été exfiltrés"}],
        "affected_systems": [{"value": "serveurs VMware ESXi", "confidence": .9, "evidence": "serveurs VMware ESXi"}],
        "affected_datasets": [{"value": "base clients", "confidence": .9, "evidence": "base clients"}],
    }
    fields = set(raw)
    result = sfa._normalize(raw, context, fields)
    assert result["attack_date"]["value"] == "2026-08-12"
    assert result["vulnerabilities"][0]["value"] == "CVE-2026-12345"
    assert result["affected_counts"][0]["value"] == 150000
    assert result["data_volumes"][0]["value"] == "2,4 To"
    assert result["file_counts"][0]["value"] == "12000"
    assert result["affected_systems"][0]["value"] == "serveurs VMware ESXi"
    assert result["affected_datasets"][0]["value"] == "base clients"


def test_cve_llm_absente_de_la_preuve_et_date_imprecise_sont_rejetee():
    context = "L'incident a eu lieu courant juillet."
    result = sfa._normalize({
        "attack_date": {"value": "2026-07-01", "confidence": .9, "evidence": "courant juillet"},
        "vulnerabilities": [{"value": "CVE-2026-99999", "confidence": .9, "evidence": "courant juillet"}],
    }, context, {"attack_date", "vulnerabilities"})
    assert result == {}


def test_prompt_precise_acteur_distinct_de_la_victime_et_impact_non_redondant():
    """Cas réels constatés (audit 2026-08-25) : threat_actor="qui"/"L'entreprise"
    (sujet grammatical d'un verbe déclaratif capté sans vérification) sur
    Groupe Bernard/Emil Frey France, et impact qui ne fait que reformuler
    les valeurs déjà extraites dans Systèmes & périmètres sur Emil Frey
    France. Le prompt n'avait aucune consigne dédiée à threat_actor, et
    aucune consigne empêchant impact de paraphraser data_types/
    affected_datasets."""
    prompt = sfa._SYSTEM_PROMPT
    assert "entité distincte de la victime" in prompt
    assert "jamais un pronom" in prompt
    assert "ne doit jamais se limiter à reformuler" in prompt
