from pathlib import Path


WORKFLOW = Path('.github/workflows/cyberattaque-rich-backfill.yml')


def test_semantic_checkpoints_use_autostash_and_fail_closed():
    text = WORKFLOW.read_text(encoding='utf-8')

    assert "git config rebase.autoStash true" in text
    assert text.count("git pull --rebase --autostash") >= 2
    assert "Échec de publication du checkpoint sémantique : arrêt immédiat" in text
    assert "exit 1" in text
    assert "Checkpoint batch ${batch} publié" in text


def test_checkpoint_files_are_committed_before_rebase():
    text = WORKFLOW.read_text(encoding='utf-8')

    add_pos = text.index("git add -- data/source_facts.csv")
    commit_pos = text.index('git commit -m "data: Cyberattaque semantic checkpoint batch ${batch}"')
    pull_pos = text.index('git pull --rebase --autostash origin "${GITHUB_REF_NAME}"')

    assert add_pos < commit_pos < pull_pos


def test_existing_backlog_skips_full_rebuild_and_uses_more_batches():
    text = WORKFLOW.read_text(encoding='utf-8')

    assert "Déterminer si le backfill peut reprendre" in text
    assert "steps.resume.outputs.resume != '1'" in text
    assert "steps.resume.outputs.resume == '1'" in text
    assert "MAX_SEMANTIC_BATCHES" in text
    assert "'14'" in text
    assert "timeout-minutes: 90" in text
    assert "NEEDED=$(( (EXISTING_BACKLOG + CALLS - 1) / CALLS + 1 ))" in text


def test_remaining_backlog_does_not_abort_before_audit_but_final_gate_is_strict():
    text = WORKFLOW.read_text(encoding='utf-8')

    assert "SEMANTIC_COMPLETE=0" in text
    assert "L'audit et le verdict vont tout de même s'exécuter" in text
    assert "exit 2" not in text
    assert "Exiger READY pour la clôture finale" in text
    strict_gate = text.split("- name: Exiger READY pour la clôture finale", 1)[1]
    strict_gate = strict_gate.split("- name: Contrôles de non-régression", 1)[0]
    assert "--allow-not-ready" not in strict_gate
