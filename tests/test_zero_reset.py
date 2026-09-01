from pathlib import Path

from cyberwatch.zero_reset import (
    PRESERVED_DATA_PATHS,
    archive,
    inventory,
    purge,
    verify_zero,
)


def _seed(root: Path) -> None:
    data = root / "data"
    site = root / "assets" / "data"
    data.mkdir(parents=True)
    site.mkdir(parents=True)
    (data / "items.csv").write_text("Item_ID\na\n", encoding="utf-8")
    (data / "incident_id_registry.csv").write_text("Incident_ID\ni\n", encoding="utf-8")
    (data / "llm_usage.json").write_text("{}", encoding="utf-8")
    (data / "temporary").mkdir()
    (data / "temporary" / "cache.json").write_text("{}", encoding="utf-8")
    for name in PRESERVED_DATA_PATHS:
        (data / name).write_text("static", encoding="utf-8")
    (site / "incidents.json").write_text("[]", encoding="utf-8")
    (site / "status.json").write_text("{}", encoding="utf-8")


def test_archive_contains_state_before_purge(tmp_path):
    _seed(tmp_path)
    output = tmp_path / "before.tgz"
    result = archive(tmp_path, output)
    assert output.exists()
    assert result["members"] >= 7
    assert result["inventory"]["count"] >= 7
    assert len(result["archive_sha256"]) == 64


def test_zero_reset_removes_runtime_identity_cache_and_site_data(tmp_path):
    _seed(tmp_path)
    report = purge(tmp_path)
    assert "data/items.csv" in report.removed
    assert "data/incident_id_registry.csv" in report.removed
    assert "data/llm_usage.json" in report.removed
    assert "data/temporary/cache.json" in report.removed
    assert "assets/data/incidents.json" in report.removed
    assert "assets/data/status.json" in report.removed
    assert not report.unexpected_preserved
    for name in PRESERVED_DATA_PATHS:
        assert (tmp_path / "data" / name).exists()
    assert verify_zero(tmp_path)["verdict"] == "ZERO"


def test_verify_zero_rejects_any_unallowlisted_survivor(tmp_path):
    _seed(tmp_path)
    purge(tmp_path)
    (tmp_path / "data" / "legacy.csv").write_text("x", encoding="utf-8")
    result = verify_zero(tmp_path)
    assert result["verdict"] == "DIRTY"
    assert result["survivors"] == ["data/legacy.csv"]


def test_inventory_is_deterministic(tmp_path):
    _seed(tmp_path)
    first = inventory(tmp_path)
    second = inventory(tmp_path)
    assert first == second
    assert [row["path"] for row in first["files"]] == sorted(row["path"] for row in first["files"])
