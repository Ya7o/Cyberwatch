from cyberwatch.collectors.base import RawEntry, SourceSpec
from cyberwatch.dedup import KEEP_SEPARATE, MERGE, decide_merge
from cyberwatch.identity import item_id
from cyberwatch.runner import entry_to_item


def test_native_source_item_id_is_stable_when_metadata_changes():
    first = item_id("SRC", "2026-01-01", "old org", "https://old", "native-42")
    corrected = item_id("SRC", "2026-01-05", "corrected org", "https://new", "native-42")
    assert first == corrected


def test_native_source_item_id_remains_namespaced_by_source():
    left = item_id("SRC-A", "2026-01-01", "org", "https://a", "native-42")
    right = item_id("SRC-B", "2026-01-01", "org", "https://a", "native-42")
    assert left != right


def test_fixture_uses_native_source_item_id_for_item_identity(make_item):
    first = make_item(
        source="A",
        source_item_id="42",
        published="2026-01-01",
        org="Ancien nom",
        url="https://old",
    )
    corrected = make_item(
        source="A",
        source_item_id="42",
        published="2026-01-02",
        org="Nouveau nom",
        url="https://new",
    )
    assert first.Item_ID == corrected.Item_ID


def test_runner_preserves_native_source_item_id():
    entry = RawEntry(
        title="Organisation exemple",
        url="https://example.org/item/42",
        source_item_id="native-42",
        published="2026-01-01",
        organisation="Organisation exemple",
    )
    spec = SourceSpec(
        source_id="TEST_SOURCE",
        layer="FR_CORE",
        zone="FR",
        default_threat="Fuite de données",
    )
    item = entry_to_item(entry, spec, "2026-08-14T00:00:00+04:00", {}, {}, {}, {})
    assert item is not None
    assert item.Source_Item_ID == "native-42"
    assert item.Item_ID == item_id(
        "TEST_SOURCE",
        "2026-01-01",
        item.Organisation_Key,
        "https://example.org/item/42",
        "native-42",
    )


def test_ransomware_shared_url_is_never_a_unique_url_signal(make_item):
    left = make_item(
        source="RANSOMWARE_LIVE",
        published="2026-01-01",
        url="http://shared.onion",
    )
    right = make_item(
        source="RANSOMWARE_LIVE",
        published="2026-01-10",
        url="http://shared.onion",
    )
    decision = decide_merge(left, right)
    assert decision.action == KEEP_SEPARATE
    assert decision.reason_code == "INCIDENT_KEEP_TIME_GAP"


def test_unlisted_source_url_is_not_a_global_identity_signal(make_item):
    left = make_item(source="SOURCE_A", published="2026-01-01", url="https://shared.example/item")
    right = make_item(source="SOURCE_A", published="2026-01-10", url="https://shared.example/item")
    assert decide_merge(left, right).action == KEEP_SEPARATE


def test_allowlisted_source_unique_url_is_strong_between_four_and_fourteen_days(make_item):
    left = make_item(
        source="CYBERATTAQUE_ORG",
        published="2026-01-01",
        url="https://cyberattaque.org/item-42",
    )
    right = make_item(
        source="CYBERATTAQUE_ORG",
        published="2026-01-10",
        url="https://cyberattaque.org/item-42",
    )
    decision = decide_merge(left, right)
    assert decision.action == MERGE
    assert decision.reason_code == "INCIDENT_MERGE_UNIQUE_URL"


def test_same_external_url_across_sources_is_not_sufficient(make_item):
    left = make_item(
        source="CYBERATTAQUE_ORG",
        published="2026-01-01",
        url="https://example.org/shared",
    )
    right = make_item(
        source="FRENCHBREACHES",
        published="2026-01-10",
        url="https://example.org/shared",
    )
    assert decide_merge(left, right).action == KEEP_SEPARATE
