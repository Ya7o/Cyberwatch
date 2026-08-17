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
