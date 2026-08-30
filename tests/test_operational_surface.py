from pathlib import Path
import re
import textwrap


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def test_operational_workflow_surface_is_intentionally_small():
    workflow_names = sorted(path.name for path in WORKFLOWS.glob("*.yml"))
    assert workflow_names == [
        "ci.yml", "cold-reset.yml", "collect.yml", "dispatch-reset-20260830.yml",
        "reset-validation-five-cases.yml", "source-facts-backfill.yml",
    ]


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


def test_five_cases_reset_is_manual_and_requires_explicit_confirmation():
    content = (WORKFLOWS / "reset-validation-five-cases.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" in content
    assert "schedule:" not in content
    assert "FIVE_CASES_RESET" in content
    assert "validation/five_cases.json" in content


def test_five_cases_reset_embedded_budget_script_compiles():
    """Le garde-fou financier ne doit pas bloquer la publication par syntaxe."""
    content = (WORKFLOWS / "reset-validation-five-cases.yml").read_text(encoding="utf-8")
    match = re.search(
        r"python - <<'PY'\n(?P<script>.*?)\n\s+PY\n",
        content,
        flags=re.DOTALL,
    )
    assert match, "script Python de budget introuvable"
    compile(textwrap.dedent(match.group("script")), "reset-validation-budget", "exec")


def test_cold_reset_certifies_before_publication():
    content = (WORKFLOWS / "cold-reset.yml").read_text(encoding="utf-8")
    audit_pos = content.index("python -m cyberwatch.reset_baseline audit")
    baseline_pos = content.index("data/post_reset_baseline.json")
    publish_pos = content.index("- name: Publier")
    assert audit_pos < publish_pos
    assert baseline_pos < publish_pos
    assert "/tmp/reset-baseline-before.json" in content
    assert "/tmp/reset-audit.json" in content
