from scripts.certify_cyberattaque_semantic_closeout import evaluate


def test_closeout_ready_when_backlog_and_retryables_are_empty():
    result = evaluate(
        {"backlog_remaining": 0, "pending": 0, "failed_retryable": 0, "cache_hits": 12},
        {"certified": True},
    )
    assert result["ready"] is True
    assert result["status"] == "READY"
    assert result["reasons"] == []


def test_closeout_not_ready_when_backlog_remains():
    result = evaluate(
        {"backlog_remaining": 3, "pending": 2, "failed_retryable": 1},
        {"certified": True},
    )
    assert result["ready"] is False
    assert result["status"] == "NOT_READY"
    assert "backlog_empty" in result["reasons"]
    assert "pending_empty" in result["reasons"]
    assert "failed_retryable_empty" in result["reasons"]


def test_closeout_not_ready_without_semantic_certification():
    result = evaluate(
        {"backlog_remaining": 0, "pending": 0, "failed_retryable": 0},
        {"certified": False},
    )
    assert result["ready"] is False
    assert result["checks"]["semantic_certified"] is False


def test_closeout_not_ready_when_inputs_are_missing():
    result = evaluate({}, {})
    assert result["ready"] is False
    assert result["checks"]["progress_present"] is False
    assert result["checks"]["certification_present"] is False
