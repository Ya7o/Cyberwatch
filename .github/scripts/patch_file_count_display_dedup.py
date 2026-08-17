from pathlib import Path

js_path = Path("assets/dashboard-audit.js")
js = js_path.read_text(encoding="utf-8")

anchor = '''  function factLinks(fact) {'''
helper = '''  function duplicatesDedicatedFileCount(fact) {
    if (String(fact.affected_unit || "").trim().toLowerCase() !== "files") return false;
    if (fact.affected_count === undefined || fact.affected_count === null || fact.affected_count === "") return false;
    if (fact.file_count === undefined || fact.file_count === null || fact.file_count === "") return false;
    const affected = Number(fact.affected_count);
    const files = Number(fact.file_count);
    return Number.isFinite(affected) && Number.isFinite(files) && affected === files;
  }

  function factLinks(fact) {'''
if anchor not in js:
    raise SystemExit("factLinks anchor not found")
if "function duplicatesDedicatedFileCount(fact)" not in js:
    js = js.replace(anchor, helper, 1)

old_row = '      factRow("Données touchées", affectedLabel(fact)),'
new_row = '      factRow("Données touchées", duplicatesDedicatedFileCount(fact) ? "" : affectedLabel(fact)),'
if old_row not in js and new_row not in js:
    raise SystemExit("affected count row not found")
js = js.replace(old_row, new_row, 1)
js_path.write_text(js, encoding="utf-8")

test_path = Path("tests/test_site_source_facts.py")
test = test_path.read_text(encoding="utf-8")
test_name = "def test_renderer_ui_ne_duplique_pas_affected_files_et_file_count():"
if test_name not in test:
    test += '''\n\ndef test_renderer_ui_ne_duplique_pas_affected_files_et_file_count():\n    js = open("assets/dashboard-audit.js", encoding="utf-8").read()\n    assert "function duplicatesDedicatedFileCount(fact)" in js\n    assert 'affected_unit || "").trim().toLowerCase() !== "files"' in js\n    assert 'factRow("Données touchées", duplicatesDedicatedFileCount(fact) ? "" : affectedLabel(fact))' in js\n    # Le compteur dédié reste affiché : si les deux valeurs diffèrent, les deux lignes gardent leur sens.\n    assert 'factRow("Fichiers", fact.file_count !== undefined ? formatNumber(fact.file_count) : "")' in js\n'''
    test_path.write_text(test, encoding="utf-8")
