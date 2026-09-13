"""Politique de cible pour une URL fournie par un tiers, avant tout fetch.

Cette couche répond à une seule question : « a-t-on le droit d'aller chercher
cette URL ? ». Elle est délibérément générique et non rattachée à un moteur
particulier : tout composant qui reçoit une URL d'une source qu'il ne contrôle
pas — provider externe, page téléchargée, réponse d'API — doit la traverser.

Le contrat est celui du reste du projet : **un refus n'est jamais une
exception**, c'est un code de motif. Rien ici n'émet de requête HTTP ; la seule
opération réseau est la résolution DNS, et elle est injectable pour que les
tests et le benchmark restent hors ligne.

Deux choix volontairement plus stricts que nécessaire, parce qu'un faux négatif
coûte une page non lue et un faux positif coûte une requête vers un service
interne :

* **tout littéral IP est refusé**, même public. Cyberwatch n'en a jamais besoin,
  et l'interdire supprime d'un coup les encodages décimal, octal et hexadécimal
  (``2130706433``, ``0x7f.1``) ainsi que les formes IPv6 mappées ;
* **toutes** les adresses résolues doivent être publiques. Un hôte qui répond
  une adresse publique et une privée est refusé en entier : c'est la forme
  classique d'évasion par horizon partagé.
"""

from __future__ import annotations

import ipaddress
import socket
from functools import lru_cache
from typing import Callable
from urllib.parse import urlsplit

#: Une URL plus longue que cela ne vient pas d'un site qu'on veut lire.
MAX_URL_CHARS = 2048

ALLOWED_SCHEMES = frozenset({"http", "https"})
#: Ports par schéma. Un port exotique désigne un service, pas un site public.
ALLOWED_PORTS = {"http": {80}, "https": {443}}

REASON_TOO_LONG = "URL_TOO_LONG"
REASON_SCHEME = "URL_SCHEME_REJECTED"
REASON_CREDENTIALS = "URL_CREDENTIALS_REJECTED"
REASON_PORT = "URL_PORT_REJECTED"
REASON_HOST = "URL_HOST_REJECTED"
REASON_IP_LITERAL = "URL_IP_LITERAL_REJECTED"
REASON_INTERNAL_SUFFIX = "URL_INTERNAL_SUFFIX_REJECTED"
REASON_UNRESOLVABLE = "URL_UNRESOLVABLE_HOST"
REASON_PRIVATE = "URL_PRIVATE_ADDRESS_REJECTED"

#: Tous les motifs de refus, pour que les appelants puissent les énumérer.
REASONS = frozenset({
    REASON_TOO_LONG, REASON_SCHEME, REASON_CREDENTIALS, REASON_PORT, REASON_HOST,
    REASON_IP_LITERAL, REASON_INTERNAL_SUFFIX, REASON_UNRESOLVABLE, REASON_PRIVATE,
})

#: Noms d'hôte connus pour désigner la machine locale ou un service de
#: métadonnées d'hébergeur. `localhost` est déjà couvert par la règle du nom
#: mono-label ; il figure ici pour que l'intention reste lisible.
_INTERNAL_HOSTS = frozenset({
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "metadata", "metadata.google.internal", "instance-data",
})

#: Suffixes réservés à un usage local, documentaire ou non routable.
_INTERNAL_SUFFIXES = (
    ".local", ".internal", ".localdomain", ".home.arpa",
    ".onion", ".test", ".invalid", ".example",
)

Resolver = Callable[[str], list[str]]


def _public(address: str) -> bool:
    """Vrai si l'adresse est globalement routable, formes mappées comprises."""
    try:
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(address)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return ip.is_global and not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def _system_resolver(host: str) -> list[str]:
    """Toutes les adresses A et AAAA connues pour cet hôte."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return [str(info[4][0]) for info in infos]


@lru_cache(maxsize=256)
def _cached_resolver(host: str) -> tuple[str, ...]:
    """Résolution mémorisée : le garde de redirection revoit les mêmes hôtes."""
    return tuple(_system_resolver(host))


def _default_resolver(host: str) -> list[str]:
    return list(_cached_resolver(host))


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def address_rejection(host: str, *, resolver: Resolver | None = None) -> str:
    """Motif de refus des adresses d'un hôte, ou `""` si toutes sont publiques.

    Un hôte irrésoluble est distingué d'un hôte privé : le premier est une
    panne ou une coquille, le second une tentative d'atteindre le réseau
    interne. Les confondre effacerait précisément le signal intéressant.
    """
    resolve = resolver or _default_resolver
    try:
        addresses = resolve(host)
    except (OSError, UnicodeError):
        return REASON_UNRESOLVABLE
    if not addresses:
        return REASON_UNRESOLVABLE
    if not all(_public(address) for address in addresses):
        return REASON_PRIVATE
    return ""


def url_rejection(url: str, *, resolver: Resolver | None = None,
                  require_https: bool = False) -> str:
    """Motif de refus d'une URL candidate, ou `""` si elle est admissible.

    L'ordre des contrôles va du moins coûteux au plus coûteux : la résolution
    DNS n'est tentée qu'une fois la forme de l'URL entièrement validée.
    """
    raw = (url or "").strip()
    if not raw or len(raw) > MAX_URL_CHARS:
        return REASON_TOO_LONG if raw else REASON_HOST
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return REASON_HOST

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES or (require_https and scheme != "https"):
        return REASON_SCHEME
    if parsed.username or parsed.password or "@" in parsed.netloc:
        return REASON_CREDENTIALS
    try:
        port = parsed.port
    except ValueError:
        return REASON_PORT
    if port is not None and port not in ALLOWED_PORTS[scheme]:
        return REASON_PORT

    host = (parsed.hostname or "").strip().rstrip(".").lower()
    if not host or any(ch.isspace() for ch in host) or "_" in host:
        return REASON_HOST
    try:
        host.encode("idna")
    except UnicodeError:
        return REASON_HOST
    if _is_ip_literal(host) or _is_ip_literal(parsed.netloc.split("@")[-1]):
        return REASON_IP_LITERAL
    # Un nom mono-label ne désigne aucun site public : c'est `localhost`, un nom
    # de machine du réseau local, ou un service résolu par un suffixe de
    # recherche DHCP.
    if "." not in host or host in _INTERNAL_HOSTS or host.endswith(_INTERNAL_SUFFIXES):
        return REASON_INTERNAL_SUFFIX

    return address_rejection(host, resolver=resolver)


def safe_url(url: str, *, resolver: Resolver | None = None,
             require_https: bool = False) -> bool:
    """Forme booléenne, pour les appelants qui n'ont pas besoin du motif."""
    return not url_rejection(url, resolver=resolver, require_https=require_https)


def hop_guard(*, resolver: Resolver | None = None,
              require_https: bool = False) -> Callable[[str], str]:
    """Garde applicable à chaque saut d'une chaîne de redirection.

    Destiné à ``HttpClient.fetch(url_guard=...)`` : la politique est décidée
    ici, une fois, et rejouée sur chaque saut réellement suivi par la couche
    HTTP — y compris le dernier, qui est celui dont le corps sera lu.
    """
    def guard(candidate: str) -> str:
        return url_rejection(candidate, resolver=resolver, require_https=require_https)

    return guard
