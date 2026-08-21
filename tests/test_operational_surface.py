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


def test_cold_reset_certifies_before_publication():
    content = (WORKFLOWS / "cold-reset.yml").read_text(encoding="utf-8")
    audit_pos = content.index("python -m cyberwatch.reset_baseline audit")
    baseline_pos = content.index("data/post_reset_baseline.json")
    publish_pos = content.index("- name: Publier")
    assert audit_pos < publish_pos
    assert baseline_pos < publish_pos
    assert "/tmp/reset-baseline-before.json" in content
    assert "/tmp/reset-audit.json" in content
