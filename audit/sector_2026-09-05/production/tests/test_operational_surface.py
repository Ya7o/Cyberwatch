from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def test_operational_workflow_surface_is_intentionally_small():
    workflow_names = sorted(path.name for path in WORKFLOWS.glob("*.yml"))
    assert workflow_names == ["ci.yml", "collect.yml"]


def test_collect_is_the_only_scheduled_data_workflow():
    scheduled = []
    for path in WORKFLOWS.glob("*.yml"):
        if "schedule:" in path.read_text(encoding="utf-8"):
            scheduled.append(path.name)
    assert scheduled == ["collect.yml"]


def test_collect_publishes_directly_on_main_without_prod_branch():
    content = (WORKFLOWS / "collect.yml").read_text(encoding="utf-8")
    assert "git push origin HEAD:main" in content
    assert "origin/prod" not in content
    assert "HEAD:prod" not in content
    assert "git worktree" not in content


def test_collect_exposes_only_daily_update():
    content = (WORKFLOWS / "collect.yml").read_text(encoding="utf-8")
    assert "python -m cyberwatch maj" in content
    assert "create" not in content


def test_collect_has_one_explicit_global_ai_budget():
    content = (WORKFLOWS / "collect.yml").read_text(encoding="utf-8")
    assert 'LLM_MAX_COST_USD_PER_RUN: "0.03"' in content
    assert content.count("MAX_COST_USD_PER_RUN") == 1
