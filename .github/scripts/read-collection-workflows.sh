#!/usr/bin/env bash
set -euo pipefail

if gh api "repos/$GITHUB_REPOSITORY/actions/workflows/collect.yml/runs?event=schedule&per_page=30" --jq '[.workflow_runs[] | {id,created_at,event,status,conclusion}]' > "$RUNNER_TEMP/collection-workflow-runs.json"; then
  mv "$RUNNER_TEMP/collection-workflow-runs.json" data/collection_workflow_runs.json
else
  rm -f data/collection_workflow_runs.json
  echo "::warning::Résultats GitHub indisponibles ; fiabilité limitée au journal publié."
fi
