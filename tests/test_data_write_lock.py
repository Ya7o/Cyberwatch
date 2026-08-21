from pathlib import Path


WORKFLOWS = (
    ".github/workflows/collect.yml",
    ".github/workflows/cold-reset.yml",
)


def test_all_data_writers_share_one_concurrency_group():
    root = Path(__file__).resolve().parents[1]
    expected = "group: cyberwatch-data-write"
    for relative in WORKFLOWS:
        text = (root / relative).read_text(encoding="utf-8")
        assert expected in text, relative
        assert "cancel-in-progress: false" in text, relative
