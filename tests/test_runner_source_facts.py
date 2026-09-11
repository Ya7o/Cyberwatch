from cyberwatch import config, runner_source_facts, source_facts_retry
from cyberwatch.collectors.base import RawEntry
from cyberwatch.model import Incident, Item


def test_published_values_prune_non_material_retries(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "SOURCE_FACTS_RETRY_QUEUE_PATH", str(tmp_path / "source_facts_retry_queue.json")
    )
    item = Item(
        Item_ID="ITM-1", Source_ID="FRENCHBREACHES",
        Organisation_Raw="Acme", Organisation_Key="acme",
        Published_Date="2026-09-11", Event_Date="2026-09-10",
        Title="Acme signale une intrusion", URL="https://example.test/acme",
    )
    entry = RawEntry(
        title=item.Title, organisation=item.Organisation_Raw,
        published=item.Published_Date, url=item.URL,
    )
    source_facts_retry.enqueue(
        item, entry,
        {"summary", "incident_summary", "threat_candidate", "attack_date",
         "activity_description"},
        "SEMANTIC_MISS",
    )
    incident = Incident(
        Incident_ID="INC-1", Organisation="Acme", Menace=config.THREAT_INTRUSION,
        Source_URLs=item.URL,
    )

    runner_source_facts.settle_published_fields(
        [{"Item_ID": item.Item_ID, "Summary": "Acme confirme une intrusion."}],
        [item], [incident],
    )

    [pending] = source_facts_retry.load()
    assert pending["pending_fields"] == ["activity_description"]
