"""Reprise en lots bornés, sous les plafonds partagés du runtime LLM."""
from __future__ import annotations


def challenge(entries: list, state, results: dict) -> None:
    from . import dedup_ai as api

    capacity_before = state.candidates_not_reviewed_capacity
    remaining = entries
    for _ in range(state.daily_max_batches):
        available = max(0, state.daily_max_candidates - state.candidates_selected)
        if not remaining:
            break
        # Le compteur décrit les paires encore différées, pas le nombre de
        # fois où une paire est passée dans le sélecteur des lots.
        state.candidates_not_reviewed_capacity = capacity_before
        selected = api._select_batch_entries(remaining, state, results, candidate_limit=available)
        if not selected:
            break
        call = api._call_batch(selected, state, results)
        if call is None:
            break  # Ni le budget ni une panne ne déclenchent un autre lot.
        api._store_batch_decisions(selected, call, state, results)
        if any(results[api.candidate_id(c)].status == api.STATUS_ERROR for c, _, _ in selected):
            break
        remaining = [entry for entry in remaining
                     if results.get(api.candidate_id(entry[0])) is not None
                     and results[api.candidate_id(entry[0])].status == api.STATUS_NOT_REVIEWED_CAPACITY]
