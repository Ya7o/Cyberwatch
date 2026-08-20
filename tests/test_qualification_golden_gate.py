from scripts.check_qualification_golden_gate import qualification_gate_failures


def _payload(*, matched=100, missing=0, ambiguous=0, accuracy=95.0, coverage=90.0, precision=98.0, wrong=1, unknown=2):
    return {
        "matched": matched,
        "missing": missing,
        "ambiguous": ambiguous,
        "fields": {
            "Sector": {
                "accuracy_pct": accuracy,
                "coverage_pct": coverage,
                "precision_when_qualified_pct": precision,
                "wrong_classification": wrong,
                "resolvable_unknown": unknown,
            }
        },
    }


def test_gate_accepts_equal_or_better_result():
    before = _payload()
    after = _payload(accuracy=96.0, coverage=92.0, precision=99.0, wrong=0, unknown=1)
    assert qualification_gate_failures(before, after) == []


def test_gate_blocks_precision_coverage_and_error_regressions():
    before = _payload()
    after = _payload(coverage=89.0, precision=97.0, wrong=2, unknown=3)
    failures = qualification_gate_failures(before, after)
    assert any("coverage_pct" in failure for failure in failures)
    assert any("precision_when_qualified_pct" in failure for failure in failures)
    assert any("wrong_classification" in failure for failure in failures)
    assert any("resolvable_unknown" in failure for failure in failures)


def test_gate_blocks_matching_regressions():
    failures = qualification_gate_failures(_payload(), _payload(matched=99, missing=1, ambiguous=1))
    assert any(failure.startswith("matched:") for failure in failures)
    assert any(failure.startswith("missing:") for failure in failures)
    assert any(failure.startswith("ambiguous:") for failure in failures)


def test_gate_supports_explicit_rounding_tolerance():
    before = _payload(precision=98.0)
    after = _payload(precision=97.95)
    assert qualification_gate_failures(before, after, tolerance_pp=0.1) == []
