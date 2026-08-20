import csv
from pathlib import Path

from scripts.promote_dedup_golden_v2 import (
    GOLDEN_V2,
    _eligible_auto_positive,
)

GOLDEN = Path("data/golden/dedup_golden.csv")
REVIEWS = Path("data/golden/dedup_reviewed_v2.csv")


def _rows(path: Path):
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _pair(row):
    return tuple(sorted((row["Left_Item_ID"], row["Right_Item_ID"])))


def test_golden_v2_is_large_stable_and_unique():
    rows = _rows(GOLDEN)
    assert len(rows) >= 150
    assert all(row["Golden_Version"] == GOLDEN_V2 for row in rows)
    pairs = [_pair(row) for row in rows]
    assert len(pairs) == len(set(pairs))
    assert all(row["Evidence"].strip() and row["Reviewed_At"].strip() for row in rows)


def test_review_ledger_is_materialized_and_linked_to_golden():
    golden_pairs = {_pair(row) for row in _rows(GOLDEN)}
    reviews = _rows(REVIEWS)
    assert len(reviews) == 80
    assert len({_pair(row) for row in reviews}) == len(reviews)
    assert all(_pair(row) in golden_pairs for row in reviews)
    assert all(row["Verdict"] == "SAME_INCIDENT" for row in reviews)
    assert all(row["Evidence"].strip() and row["Evidence_Tier"].strip() for row in reviews)
    assert sum(row["Evidence_Tier"] == "MANUAL_MISSED_DUPLICATE_REVIEW" for row in reviews) == 2


def _candidate(**overrides):
    row = {
        "Risk_Type": "POSSIBLE_FALSE_MERGE",
        "Days_Apart": "0",
        "Left_Source_ID": "BONJOURLAFUITE",
        "Right_Source_ID": "CYBERATTAQUE_ORG",
        "Left_Organisation_Key": "victime",
        "Right_Organisation_Key": "victime",
        "Left_Company_ID": "",
        "Right_Company_ID": "",
        "Left_Title": "Victime fuite de données",
        "Right_Title": "Victime : données exposées après une cyberattaque",
        "Left_URL": "https://left",
        "Right_URL": "https://right",
    }
    row.update(overrides)
    return row


def test_promotion_policy_accepts_only_conservative_cross_source_evidence():
    accepted, tier = _eligible_auto_positive(_candidate())
    assert accepted
    assert tier == "CANONICAL_IDENTITY_CROSS_SOURCE"

    assert not _eligible_auto_positive(_candidate(Right_Source_ID="BONJOURLAFUITE"))[0]
    assert not _eligible_auto_positive(_candidate(Days_Apart="2"))[0]
    assert not _eligible_auto_positive(_candidate(Right_Source_ID="UNKNOWN"))[0]
    assert not _eligible_auto_positive(
        _candidate(Right_Title="Victime : nouvelle cyberattaque et nouvelle fuite")
    )[0]
    assert not _eligible_auto_positive(
        _candidate(Right_Organisation_Key="autre-victime")
    )[0]
