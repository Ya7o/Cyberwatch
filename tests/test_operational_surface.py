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


def test_collect_exposes_only_normal_and_rebuild_modes():
    content = (WORKFLOWS / "collect.yml").read_text(encoding="utf-8")
    assert "options: [maj, create]" in content


def test_collect_has_an_explicit_ten_cent_total_ai_budget():
    content = (WORKFLOWS / "collect.yml").read_text(encoding="utf-8")
    expected = {
        "AI_MAX_ESTIMATED_COST_USD_PER_RUN": "0.02",
        "SOURCE_FACTS_AI_MAX_COST_USD_PER_RUN": "0.05",
        "LLM_ORGANISATION_SECTOR_MAX_COST_USD_PER_RUN": "0.02",
        "LLM_DEDUP_MAX_COST_USD_PER_RUN": "0.01",
    }
    for variable, value in expected.items():
        assert f'{variable}: "{value}"' in content
    assert round(sum(float(value) for value in expected.values()), 2) == 0.10
