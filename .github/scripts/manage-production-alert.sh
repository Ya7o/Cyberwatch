#!/usr/bin/env bash
set -euo pipefail

title="[Cyberwatch] Alerte production"
run_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
issue_number="$(gh issue list --state open --limit 100 --json number,title --jq 'map(select(.title == "[Cyberwatch] Alerte production")) | .[0].number // empty')"

if [[ "${JOB_STATUS:-failure}" != "success" || "${HEALTH_ALERT:-true}" == "true" ]]; then
  reasons="${HEALTH_REASONS:-Le workflow de production a échoué avant de produire son diagnostic.}"
  body="Run : ${run_url}

Diagnostic : ${reasons}"
  if [[ -n "$issue_number" ]]; then
    gh issue edit "$issue_number" --body "$body"
  else
    gh issue create --title "$title" --body "$body"
  fi
elif [[ -n "$issue_number" ]]; then
  gh issue close "$issue_number" --comment "Retour dans les cibles vérifié par ${run_url}."
fi
