from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def test_operational_workflow_surface_is_intentionally_small():
    workflow_names = sorted(path.name for path in WORKFLOWS.glob("*.yml"))
    assert workflow_names == ["ci.yml", "cold-reset.yml", "collect.yml"]


def test_cold_reset_is_manual_only():
    content = (WORKFLOWS / "cold-reset.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" in content
    assert "schedule:" not in content
    assert "push:" not in content
    assert "pull_request:" not in content


def test_collect_is_the_only_scheduled_data_workflow():
    scheduled = []
    for path in WORKFLOWS.glob("*.yml"):
        if "schedule:" in path.read_text(encoding="utf-8"):
            scheduled.append(path.name)
    assert scheduled == ["collect.yml"]
