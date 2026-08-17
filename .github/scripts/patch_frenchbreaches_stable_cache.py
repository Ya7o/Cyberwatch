from pathlib import Path

p = Path("cyberwatch/collectors/feed.py")
text = p.read_text(encoding="utf-8")
marker = '_HREF_RE = re.compile(r"""href=["\']([^"\']+)["\']""", flags=re.IGNORECASE)\n'
addition = marker + '''_DYNAMIC_BLOCK_RE = re.compile(
    r"<(?:script|style|noscript)\\b[^>]*>.*?</(?:script|style|noscript)>",
    flags=re.IGNORECASE | re.DOTALL,
)
_FRENCHBREACHES_SUFFIX_MARKERS = (
    "Alertes liées",
    "Si cet article vous a plu",
    "← Retour aux alertes",
)


def stable_frenchbreaches_detail_text(html_text: str) -> str:
    """Texte éditorial stable d'une fiche, sans blocs dynamiques hors article."""
    cleaned_html = _DYNAMIC_BLOCK_RE.sub(" ", html_text or "")
    text = " ".join(strip_html(cleaned_html).split())
    cut = len(text)
    for marker_text in _FRENCHBREACHES_SUFFIX_MARKERS:
        pos = text.find(marker_text)
        if pos > 0:
            cut = min(cut, pos)
    return text[:cut].strip()

'''
if marker not in text:
    raise SystemExit("feed marker missing")
text = text.replace(marker, addition, 1)
old = '        text = " ".join(strip_html(response.text).split())\n'
if old not in text:
    raise SystemExit("hydration marker missing")
text = text.replace(old, '        text = stable_frenchbreaches_detail_text(response.text)\n', 1)
p.write_text(text, encoding="utf-8")

Path("tests/test_feed_frenchbreaches_cache.py").write_text('''from cyberwatch.collectors.feed import stable_frenchbreaches_detail_text


def test_frenchbreaches_detail_text_ignores_dynamic_scripts_and_related_alerts():
    html_a = "<header>FrenchBreaches</header><main><h1>Incident Acme</h1><p>Un attaquant a exfiltré des données.</p><script>nonce=abc;now=1</script><h2>Alertes liées</h2><div>Alerte A</div></main>"
    html_b = "<header>FrenchBreaches</header><main><h1>Incident Acme</h1><p>Un attaquant a exfiltré des données.</p><script>nonce=xyz;now=2</script><h2>Alertes liées</h2><div>Alerte B</div></main>"
    a = stable_frenchbreaches_detail_text(html_a)
    b = stable_frenchbreaches_detail_text(html_b)
    assert a == b
    assert "Un attaquant a exfiltré des données." in a
    assert "nonce" not in a
    assert "Alertes liées" not in a
''', encoding="utf-8")
