from cyberwatch.collectors.feed import stable_frenchbreaches_detail_text


def test_frenchbreaches_detail_text_ignores_dynamic_scripts_and_related_alerts():
    html_a = "<header>FrenchBreaches</header><main><h1>Incident Acme</h1><p>Un attaquant a exfiltré des données.</p><script>nonce=abc;now=1</script><h2>Alertes liées</h2><div>Alerte A</div></main>"
    html_b = "<header>FrenchBreaches</header><main><h1>Incident Acme</h1><p>Un attaquant a exfiltré des données.</p><script>nonce=xyz;now=2</script><h2>Alertes liées</h2><div>Alerte B</div></main>"
    a = stable_frenchbreaches_detail_text(html_a)
    b = stable_frenchbreaches_detail_text(html_b)
    assert a == b
    assert "Un attaquant a exfiltré des données." in a
    assert "nonce" not in a
    assert "Alertes liées" not in a


def test_frenchbreaches_detail_text_removes_technical_theme_fragment():
    html = "<main><article><p>Fuite de données chez Bergerat Rent : 43 Go et 132 433 fichiers exposés — évite d'attendre que le header HTML soit lu + grosse amélioration de la vitesse d'apparition visuelle.</p></article></main>"
    text = stable_frenchbreaches_detail_text(html)
    assert "132 433 fichiers exposés" in text
    assert "header HTML" not in text
