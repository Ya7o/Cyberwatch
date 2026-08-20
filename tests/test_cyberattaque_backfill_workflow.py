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
