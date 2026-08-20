from cyberwatch import config
from cyberwatch.dedup import KEEP_SEPARATE, MERGE, build_incidents, decide_merge


def _pair(make_item, days=4, report_title="Victime : archives publiées après une cyberattaque"):
    claim = make_item(
        source="RANSOMWARE_LIVE",
        org="FILAIR",
        published="2026-04-13",
        threat=config.THREAT_RANSOMWARE,
        title="FILAIR revendiqué par lamashtu",
        url="https://claim.example/filair",
    )
    report_day = 13 + days
    report = make_item(
        source="CYBERATTAQUE_ORG",
        org="Filair",
        published=f"2026-04-{report_day:02d}",
        threat=config.THREAT_RANSOMWARE,
        title=report_title,
        url="https://cyberattaque.example/filair",
    )
    return claim, report


def test_ransomware_live_claim_followed_by_cyberattaque_j4_merges(make_item):
    claim, report = _pair(make_item, days=4)

    decision = decide_merge(claim, report)

    assert decision.action == MERGE
    assert decision.reason_code == "INCIDENT_MERGE_RANSOMWARE_CORROBORATION"
    assert "days=4" in decision.signals
    assert len(build_incidents([claim, report])) == 1


def test_ransomware_corroboration_is_symmetric(make_item):
    claim, report = _pair(make_item, days=4)

    assert decide_merge(claim, report) == decide_merge(report, claim)


def test_ransomware_corroboration_does_not_extend_to_j5(make_item):
    claim, report = _pair(make_item, days=5)

    assert decide_merge(claim, report).action == KEEP_SEPARATE
    assert len(build_incidents([claim, report])) == 2


def test_ransomware_corroboration_requires_exact_source_pair(make_item):
    claim, _ = _pair(make_item, days=4)
    other = make_item(
        source="FRENCHBREACHES",
        org="Filair",
        published="2026-04-17",
        threat=config.THREAT_RANSOMWARE,
        title="Filair",
        url="https://frenchbreaches.example/filair",
    )

    assert decide_merge(claim, other).action == KEEP_SEPARATE


def test_ransomware_corroboration_requires_ransomware_on_both_sides(make_item):
    claim, report = _pair(make_item, days=4)
    report.Threat = config.THREAT_LEAK

    assert decide_merge(claim, report).action == KEEP_SEPARATE


def test_recurrence_marker_remains_a_veto_at_j4(make_item):
    claim, report = _pair(
        make_item,
        days=4,
        report_title="FILAIR frappé de nouveau par une nouvelle cyberattaque",
    )

    decision = decide_merge(claim, report)

    assert decision.action == KEEP_SEPARATE
    assert decision.reason_code == "INCIDENT_KEEP_RECURRENCE_MARKER"
