from cyberwatch.collectors.base import SourceSpec
from cyberwatch.collectors.feed import parse_feed
from cyberwatch.collectors.wordpress import entry_from_post
from cyberwatch.identity import item_id


def test_wordpress_native_post_id_is_preserved():
    spec = SourceSpec("TEST", "core", "France")
    entry = entry_from_post(
        {
            "id": 1234,
            "date": "2026-04-01T10:00:00",
            "link": "https://example.test/article",
            "title": {"rendered": "Incident"},
            "excerpt": {"rendered": ""},
        },
        spec,
    )
    assert entry is not None
    assert entry.source_item_id == "1234"


def test_rss_guid_is_preserved_when_present():
    spec = SourceSpec("TEST", "core", "France")
    feed = """<?xml version="1.0"?>
    <rss version="2.0"><channel><item>
      <guid isPermaLink="false">native-42</guid>
      <title>Incident cyber</title>
      <link>https://example.test/article</link>
      <pubDate>Wed, 01 Apr 2026 10:00:00 GMT</pubDate>
    </item></channel></rss>"""
    entries = parse_feed(feed, spec)
    assert len(entries) == 1
    assert entries[0].source_item_id == "native-42"


def test_native_id_makes_item_identity_independent_of_mutable_metadata():
    first = item_id("SRC", "2026-04-01", "old name", "https://old", "native-42")
    second = item_id("SRC", "2026-04-03", "corrected name", "https://new", "native-42")
    assert first == second
