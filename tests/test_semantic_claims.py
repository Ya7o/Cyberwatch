"""Filet de garde pour l'extraction sémantique partagée (relations)."""
from cyberwatch.collectors import semantic_claims as sc


def test_relation_dont_ni_sujet_ni_objet_n_apparait_dans_la_preuve_est_rejetee():
    """Cas réel constaté sur Solimut : une relation "ZeroBytes → affects →
    systèmes de Solimut" dont la preuve ne mentionne ni ZeroBytes ni Solimut
    (ZeroBytes est l'acteur d'un autre incident du même lot) ne doit pas être
    acceptée, même si la preuve est un extrait réel de l'article."""
    article = (
        "Le cybercriminel misere revendique la mise en vente de bases de données "
        "attribuées à Solimut. Il reste donc à déterminer si l'accès initial a "
        "effectivement été neutralisé."
    )
    raw = {
        "subject": "ZeroBytes",
        "relation": "affects",
        "object": "systèmes de Solimut",
        "status": "unknown",
        "evidence": "Il reste donc à déterminer si l'accès initial a effectivement été neutralisé.",
    }
    assert sc._clean_relation(raw, article) is None


def test_relation_dont_l_objet_est_ancre_dans_la_preuve_est_acceptee():
    """Le sujet peut rester implicite (nom de l'organisation sous-entendu) tant
    que l'objet de la relation est bien cité dans la preuve elle-même."""
    article = (
        "ZeroBytes affirme pour sa part avoir commencé par le site WordPress "
        "exposé publiquement avant de découvrir un ERP accessible depuis Internet."
    )
    raw = {
        "subject": "Déclic Services",
        "relation": "compromised_via",
        "object": "WordPress",
        "status": "claimed",
        "evidence": "ZeroBytes affirme pour sa part avoir commencé par le site WordPress exposé publiquement",
    }
    cleaned = sc._clean_relation(raw, article)
    assert cleaned is not None
    assert cleaned["object"] == "WordPress"


def test_relation_dont_le_sujet_est_ancre_dans_la_preuve_est_acceptee():
    article = "ZeroBytes revendique l'accès à l'outil interne Pilot de Sport 2000."
    raw = {
        "subject": "ZeroBytes",
        "relation": "claimed_by",
        "object": "Sport 2000",
        "status": "claimed",
        "evidence": "ZeroBytes revendique l'accès à l'outil interne Pilot de Sport 2000.",
    }
    assert sc._clean_relation(raw, article) is not None
