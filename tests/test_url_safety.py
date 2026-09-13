"""Politique de cible : aucune URL de tiers ne doit atteindre le réseau interne.

Aucun test n'accède au réseau : le résolveur DNS est injecté partout.
"""
import pytest
import requests

from cyberwatch import url_safety

DNS = {
    "exemple-passpass.fr": ["93.184.216.34"],
    "v6.exemple.fr": ["2001:4860:4860::8888"],
    "split-horizon.fr": ["93.184.216.34", "10.0.0.5"],
    "prive.fr": ["10.0.0.5"],
    "mappe.fr": ["::ffff:10.0.0.1"],
}


def resolver(host):
    if host not in DNS:
        raise OSError("NXDOMAIN")
    return DNS[host]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(requests.Session, "request",
                        lambda *a, **k: pytest.fail("réseau interdit"))


def rejection(url):
    return url_safety.url_rejection(url, resolver=resolver)


def test_localhost_et_noms_mono_label_sont_refuses():
    """Un nom sans point ne désigne aucun site public : c'est la machine locale
    ou un nom résolu par un suffixe de recherche du réseau."""
    for url in ("http://localhost/about", "https://localhost/a", "https://intranet/a",
                "https://metadata.google.internal/x", "https://instance-data/x"):
        assert rejection(url) == url_safety.REASON_INTERNAL_SUFFIX, url


@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254",
    "100.64.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.1",
    "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "::",
])
def test_toutes_les_plages_non_publiques_sont_refusees(address):
    host = f"[{address}]" if ":" in address else address
    assert rejection(f"https://{host}/x") == url_safety.REASON_IP_LITERAL


@pytest.mark.parametrize("address", ["8.8.8.8", "93.184.216.34", "2001:4860:4860::8888"])
def test_un_litteral_ip_est_refuse_meme_public(address):
    """Refuser tous les littéraux supprime d'un coup les encodages décimal,
    octal et hexadécimal, et Cyberwatch n'en a jamais besoin."""
    host = f"[{address}]" if ":" in address else address
    assert rejection(f"https://{host}/x") == url_safety.REASON_IP_LITERAL


def test_identifiants_et_ports_non_standard_sont_refuses():
    assert rejection("https://user:pw@exemple-passpass.fr/") == url_safety.REASON_CREDENTIALS
    assert rejection("https://user@exemple-passpass.fr/") == url_safety.REASON_CREDENTIALS
    assert rejection("https://exemple-passpass.fr:8080/") == url_safety.REASON_PORT
    assert rejection("https://exemple-passpass.fr:443/ok") == ""
    assert rejection("http://exemple-passpass.fr:80/ok") == ""


@pytest.mark.parametrize("suffix", [".local", ".internal", ".localdomain", ".home.arpa",
                                    ".onion", ".test", ".invalid", ".example"])
def test_les_suffixes_reserves_sont_refuses(suffix):
    assert rejection(f"https://acme{suffix}/a") == url_safety.REASON_INTERNAL_SUFFIX


def test_schemas_hors_http_sont_refuses():
    for url in ("ftp://exemple-passpass.fr/", "file:///etc/passwd",
                "gopher://exemple-passpass.fr/"):
        assert rejection(url) == url_safety.REASON_SCHEME
    assert url_safety.url_rejection("http://exemple-passpass.fr/x", resolver=resolver,
                                    require_https=True) == url_safety.REASON_SCHEME


def test_hote_irresoluble_est_distingue_de_hote_prive():
    """Une coquille et une tentative d'atteindre le réseau interne n'appellent
    pas la même lecture : les confondre effacerait le signal intéressant."""
    assert rejection("https://inconnu-ici.fr/a") == url_safety.REASON_UNRESOLVABLE
    assert rejection("https://prive.fr/a") == url_safety.REASON_PRIVATE


def test_un_hote_avec_une_seule_reponse_privee_est_refuse_en_entier():
    """Horizon partagé : une adresse publique ne rachète pas une adresse privée."""
    assert rejection("https://split-horizon.fr/a") == url_safety.REASON_PRIVATE
    assert rejection("https://mappe.fr/a") == url_safety.REASON_PRIVATE


def test_les_cibles_publiques_restent_acceptees():
    assert rejection("https://exemple-passpass.fr/qui-sommes-nous") == ""
    assert rejection("https://v6.exemple.fr/a") == ""
    assert url_safety.safe_url("https://exemple-passpass.fr/a", resolver=resolver)


def test_url_degenerees_sont_refusees_sans_resolution():
    assert rejection("") == url_safety.REASON_HOST
    assert rejection("https://a_b.fr/x") == url_safety.REASON_HOST
    assert rejection("https://" + "a" * 2100 + ".fr/") == url_safety.REASON_TOO_LONG


def test_le_garde_de_saut_applique_la_meme_politique():
    guard = url_safety.hop_guard(resolver=resolver)
    assert guard("https://exemple-passpass.fr/a") == ""
    assert guard("http://169.254.169.254/latest/meta-data/") == url_safety.REASON_IP_LITERAL
