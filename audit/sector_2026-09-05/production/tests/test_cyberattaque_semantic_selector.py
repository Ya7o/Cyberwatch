from cyberwatch.collectors.cyberattaque_semantic_selector import decide


def test_long_article_alone_does_not_trigger_llm():
    decision = decide("Incident simple. " * 1000, {})
    assert decision.use_llm is False
    assert decision.reasons == ()


def test_existing_richness_alone_does_not_trigger_llm():
    deterministic = {
        "affected_counts": [{}, {}],
        "data_volumes": [{}],
        "timeline": [{}, {}],
        "relations": [{}],
        "data_types": [{}],
    }
    decision = decide("Incident confirmé sans ambiguïté particulière.", deterministic)
    assert decision.use_llm is False


def test_ambiguity_and_negation_trigger_llm():
    ambiguous = decide("Selon le groupe, les données pourraient avoir été exfiltrées.", {})
    negated = decide("L'entreprise indique que les systèmes ne sont pas affectés.", {})
    assert ambiguous.use_llm is True
    assert "ambiguous_claim" in ambiguous.reasons
    assert negated.use_llm is True
    assert "negation_detected" in negated.reasons


def test_unresolved_third_party_relation_triggers_but_existing_relation_does_not():
    text = "L'incident implique un prestataire cloud de la victime."
    missing = decide(text, {})
    present = decide(text, {"relations": [{"subject": "victime", "object": "prestataire"}]})
    assert missing.use_llm is True
    assert "missing_third_party_relation" in missing.reasons
    assert present.use_llm is False


def test_selection_version_is_persistable():
    payload = decide("Un article simple.", {}).as_dict()
    assert payload["version"] == "2"
    assert payload["use_llm"] is False
