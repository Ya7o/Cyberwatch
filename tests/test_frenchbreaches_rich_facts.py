from cyberwatch.collectors.frenchbreaches_rich import extract_frenchbreaches_rich_facts


def test_frenchbreaches_uses_generic_rich_facts_without_semantic_llm():
    rich = extract_frenchbreaches_rich_facts(
        "Le groupe revendique 12 345 victimes et 8,4 Go de données. "
        "Les données pourraient comprendre des adresses e-mail."
    )
    assert rich is not None
    assert rich["engine"] == "generic-rich-facts"
    assert rich["semantic"]["used"] is False
    assert any(row["value"] == 12345 for row in rich["affected_counts"])
    assert any(row["value"] == 8.4 for row in rich["data_volumes"])
    assert any(row["value"] == "adresses e-mail" and row["status"] == "hypothesis" for row in rich["data_types"])
