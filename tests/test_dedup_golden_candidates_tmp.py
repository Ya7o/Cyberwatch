from cyberwatch import store
from cyberwatch.dedup_metrics import weak_merge_rows


def test_print_current_weak_merge_candidates():
    rows = weak_merge_rows(store.load_items())
    assert False, repr(rows[:40])
