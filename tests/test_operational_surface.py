from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def test_operational_workflow_surface_is_intentionally_small():
    workflow_names = sorted(path.name for path in WORKFLOWS.glob("*.yml"))
    assert workflow_names == ["ci.yml", "collect.yml", "monitor.yml"]


def test_collect_is_the_only_scheduled_data_workflow():
    scheduled = []
    for path in WORKFLOWS.glob("*.yml"):
        if "schedule:" in path.read_text(encoding="utf-8"):
            scheduled.append(path.name)
    assert sorted(scheduled) == ["collect.yml", "monitor.yml"]


def test_collect_publishes_directly_on_main_without_prod_branch():
    content = (WORKFLOWS / "collect.yml").read_text(encoding="utf-8")
    assert "git push origin HEAD:main" in content
    assert "origin/prod" not in content
    assert "HEAD:prod" not in content
    assert "git worktree" not in content


def test_collect_refuse_de_publier_si_main_change_pendant_le_run():
    content = (WORKFLOWS / "collect.yml").read_text(encoding="utf-8")
    assert "CYBERWATCH_BASE_COMMIT: ${{ github.sha }}" in content
    assert 'git fetch origin main' in content
    assert 'git rev-parse origin/main' in content
    assert '!= "$CYBERWATCH_BASE_COMMIT"' in content
    assert "git pull --rebase origin main" not in content


def test_collect_exposes_daily_update_and_explicit_manual_purge():
    content = (WORKFLOWS / "collect.yml").read_text(encoding="utf-8")
    assert "python -m cyberwatch maj" in content
    assert "python -m cyberwatch purge" in content
    assert "github.event_name == 'workflow_dispatch' && inputs.operation == 'PURGE'" in content
    assert "default: MAJ" in content
    assert "create" not in content


def test_collect_has_one_explicit_global_ai_budget():
    content = (WORKFLOWS / "collect.yml").read_text(encoding="utf-8")
    assert 'LLM_MAX_COST_USD_PER_RUN: "0.03"' in content
    assert content.count("MAX_COST_USD_PER_RUN") == 1


def test_ci_installe_les_dependances_de_dev_et_execute_toute_la_suite():
    content = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    assert "pip install -r requirements-dev.txt" in content
    assert "python -m pytest tests/ -q" in content
    assert "python -m pip_audit -r requirements-dev.txt" in content
    assert "python -m cyberwatch check" in content
    assert "git diff --exit-code -- assets/data" in content
    assert "tests/test_normalize.py" not in content


def test_collecte_n_installe_que_les_dependances_d_execution():
    content = (WORKFLOWS / "collect.yml").read_text(encoding="utf-8")
    assert "pip install -r requirements.txt" in content
    assert "requirements-dev.txt" not in content


def test_suivi_fraicheur_et_notification_sont_planifies():
    collect = (WORKFLOWS / "collect.yml").read_text(encoding="utf-8")
    monitor = (WORKFLOWS / "monitor.yml").read_text(encoding="utf-8")
    notifier = (ROOT / ".github" / "scripts" / "manage-production-alert.sh").read_text(encoding="utf-8")

    assert "python -m cyberwatch production-status --markdown --github-output" in collect
    assert 'cron: "17 */6 * * *"' in monitor
    assert "issues: write" in monitor
    assert "gh issue create" in notifier
    assert "gh issue close" in notifier


def test_dependances_runtime_et_developpement_sont_separees():
    runtime = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    development = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
    assert "pytest" not in runtime
    assert "pip-audit" not in runtime
    assert "-r requirements.txt" in development
    assert "pytest==9.1.1" in development
    assert "pip-audit==2.10.1" in development
    assert "ruff==0.16.5" in development
    assert "mypy==2.3.1" in development


def test_ci_execute_lint_et_typage_progressif():
    content = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert "python -m ruff check cyberwatch scripts tests" in content
    assert "python scripts/code_health.py --module-budget 0 --function-budget 0" in content
    assert "python -m mypy" in content
    assert '[tool.ruff.lint]' in pyproject
    assert '[tool.mypy]' in pyproject
    assert '"cyberwatch/production.py"' in pyproject
    assert '"cyberwatch/site_status.py"' in pyproject


def test_gouvernance_git_et_cadre_editorial_sont_versionnes():
    governance = (ROOT / "docs" / "GIT_GOVERNANCE.md").read_text(encoding="utf-8")
    editorial = (ROOT / "docs" / "EDITORIAL_POLICY.md").read_text(encoding="utf-8")
    assert "aucun nouveau tag `archive/*`" in governance
    assert "réécriture de `main`" in governance
    assert "issues GitHub" in editorial
    assert (ROOT / "LICENSE").read_text(encoding="utf-8").startswith("MIT License")
    assert (ROOT / "scripts" / "git_governance_audit.py").exists()
