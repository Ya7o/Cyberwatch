"""Couche HTTP : politesse, reprises, robots.txt et plafonds durs.

Cette couche est le garde-fou de volumétrie du projet. Aucun collecteur ne fait
d'appel réseau directement : tous passent par `HttpClient`, ce qui garantit que
les plafonds de `config` s'appliquent partout, sans exception possible. Le
budget temps porte uniquement sur le travail HTTP, jamais sur le temps passé
entre deux requêtes dans un enrichissement externe comme OpenAI.
"""

from __future__ import annotations

import time
import urllib.robotparser
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse

import requests

from . import config, status


@dataclass
class FetchResult:
    """Résultat d'une requête, y compris en échec — jamais d'exception nue."""

    ok: bool
    url: str
    status_code: int = 0
    text: str = ""
    reason_code: str = status.REASON_OK
    elapsed: float = 0.0
    headers: dict = field(default_factory=dict)
    #: URL réellement lue, après redirections. Vide = identique à `url`.
    final_url: str = ""

    def json(self):
        """Corps interprété en JSON, ou `None` si le corps n'en est pas."""
        import json

        try:
            return json.loads(self.text)
        except (ValueError, TypeError):
            return None


class Budget:
    """Compteur de requêtes et de temps HTTP consommé, avec plafonds durs.

    Un budget épuisé n'interrompt jamais brutalement le run : le collecteur en
    cours s'arrête proprement et la source est marquée `PARTIAL` avec sa
    couverture réelle. Les données déjà collectées sont conservées.
    """

    def __init__(self, max_requests: int, max_seconds: float, label: str = ""):
        self.max_requests = max_requests
        self.max_seconds = max_seconds
        self.label = label
        self.requests_made = 0
        self.seconds_spent = 0.0

    @property
    def elapsed(self) -> float:
        """Temps réellement consommé à l'intérieur de `HttpClient.fetch`."""
        return self.seconds_spent

    @property
    def exhausted(self) -> bool:
        return (
            self.requests_made >= self.max_requests
            or self.seconds_spent >= self.max_seconds
        )

    def remaining_requests(self) -> int:
        return max(0, self.max_requests - self.requests_made)

    def consume(self, count: int = 1) -> None:
        self.requests_made += count

    def consume_seconds(self, seconds: float) -> None:
        self.seconds_spent += max(0.0, float(seconds))

    def reset_clock(self) -> None:
        self.seconds_spent = 0.0


class HttpClient:
    """Client HTTP unique du projet.

    Trois garanties : un délai de politesse par domaine, un plafond de requêtes
    global et par source, et un respect du `robots.txt` de chaque site.
    """

    def __init__(
        self,
        run_budget: Budget | None = None,
        polite_delay: float = config.HTTP_POLITE_DELAY_SECONDS,
        timeout: int = config.HTTP_TIMEOUT_SECONDS,
        respect_robots: bool = True,
        max_redirects: int = config.HTTP_MAX_REDIRECTS,
    ):
        self.run_budget = run_budget or Budget(
            config.MAX_REQUESTS_PER_RUN, config.MAX_SECONDS_PER_RUN, "run"
        )
        self.polite_delay = polite_delay
        self.timeout = timeout
        self.respect_robots = respect_robots

        self.session = requests.Session()
        self.session.max_redirects = max_redirects
        self.session.headers.update(
            {
                "User-Agent": config.HTTP_USER_AGENT,
                "Accept-Language": "fr,en;q=0.8",
            }
        )
        self._last_request_at: dict[str, float] = {}
        self._robots_cache: dict[str, urllib.robotparser.RobotFileParser | None] = {}
        #: Hôtes ayant refusé l'agent identifié : on y emploie directement le
        #: repli, pour ne pas gaspiller une requête sur deux.
        self._fallback_hosts: set[str] = set()

    # ------------------------------------------------------------------
    # robots.txt
    # ------------------------------------------------------------------

    def _robots_for(self, url: str):
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin in self._robots_cache:
            return self._robots_cache[origin]

        parser = urllib.robotparser.RobotFileParser()
        parser.set_url(f"{origin}/robots.txt")
        try:
            response = self.session.get(
                f"{origin}/robots.txt", timeout=self.timeout
            )
            if response.status_code == 200:
                parser.parse(response.text.splitlines())
            else:
                # Pas de robots.txt exploitable : le site n'interdit rien.
                parser = None
        except requests.RequestException:
            parser = None

        self._robots_cache[origin] = parser
        return parser

    def allowed(self, url: str) -> bool:
        """Vrai si le `robots.txt` du site autorise ce chemin."""
        if not self.respect_robots:
            return True
        parser = self._robots_for(url)
        if parser is None:
            return True
        try:
            return parser.can_fetch(config.HTTP_USER_AGENT, url)
        except Exception:
            return True

    # ------------------------------------------------------------------
    # Requête
    # ------------------------------------------------------------------

    def _wait_politely(self, host: str) -> None:
        last = self._last_request_at.get(host)
        if last is not None:
            gap = time.monotonic() - last
            if gap < self.polite_delay:
                time.sleep(self.polite_delay - gap)
        self._last_request_at[host] = time.monotonic()

    def fetch(
        self,
        url: str,
        source_budget: Budget | None = None,
        headers: dict | None = None,
        *,
        allow_redirects: bool = True,
        max_content_bytes: int = 0,
        allowed_content_types: tuple[str, ...] = (),
        url_guard: Callable[[str], str] | None = None,
    ) -> FetchResult:
        """Récupère une URL sans lever d'exception réseau et sous budgets.

        Les quatre paramètres nommés servent aux lectures d'URL fournies par un
        tiers ; ils sont inertes par défaut, donc les collecteurs du référentiel
        conservent exactement le comportement d'avant. Voir :meth:`_received`
        pour la politique de redirection et ses limites.
        """
        if url_guard is not None and url_guard(url):
            return FetchResult(False, url, reason_code=status.REASON_URL_REJECTED)
        if self.run_budget.exhausted:
            return FetchResult(False, url, reason_code=status.REASON_BUDGET_RUN)
        if source_budget is not None and source_budget.exhausted:
            return FetchResult(False, url, reason_code=status.REASON_BUDGET_SOURCE)
        if not self.allowed(url):
            return FetchResult(False, url, reason_code=status.REASON_ROBOTS)

        host = urlparse(url).netloc
        attempt = 0
        started = time.monotonic()
        tried_fallback_ua = False
        # Les options ne sont transmises que si elles sont réellement demandées :
        # l'appel garde ainsi sa forme historique pour les collecteurs du
        # référentiel, y compris pour une session doublée qui ignorerait ces noms.
        options: dict = {}
        if not allow_redirects:
            options["allow_redirects"] = False
        if max_content_bytes > 0:
            options["stream"] = True

        try:
            while attempt <= config.HTTP_MAX_RETRIES:
                self._wait_politely(host)
                self.run_budget.consume()
                if source_budget is not None:
                    source_budget.consume()

                request_headers = dict(headers or {})
                if host in self._fallback_hosts:
                    request_headers["User-Agent"] = config.HTTP_USER_AGENT_FALLBACK

                try:
                    response = self.session.get(
                        url, timeout=self.timeout, headers=request_headers, **options
                    )
                except (requests.Timeout, requests.RequestException) as error:
                    attempt += 1
                    if attempt > config.HTTP_MAX_RETRIES:
                        reason = (status.REASON_TIMEOUT
                                  if isinstance(error, requests.Timeout)
                                  else status.REASON_HTTP_ERROR)
                        return FetchResult(False, url, reason_code=reason,
                                           elapsed=time.monotonic() - started)
                    time.sleep(2 ** attempt)
                    continue

                # 403 alors que le robots.txt autorise le chemin : le refus vient
                # d'un pare-feu qui filtre sur l'agent, pas d'une politique
                # d'exclusion. On réessaie une fois sous une forme que ces
                # pare-feux acceptent, sans masquer l'identité du projet. Une
                # fois ce repli épuisé, un 403 est définitif et rendu tel quel.
                retry_403 = not tried_fallback_ua and host not in self._fallback_hosts
                result = self._received(response, url, started, url_guard=url_guard,
                                        max_content_bytes=max_content_bytes,
                                        allowed_content_types=allowed_content_types,
                                        retry_403=retry_403)
                if result is not None:
                    return result

                code = response.status_code
                if code == 403:
                    tried_fallback_ua = True
                    self._fallback_hosts.add(host)
                    continue

                attempt += 1
                if attempt > config.HTTP_MAX_RETRIES:
                    reason = (status.REASON_HTTP_429 if code == 429
                              else status.REASON_HTTP_ERROR)
                    return FetchResult(False, url, code, "", reason,
                                       time.monotonic() - started)
                time.sleep(2 ** attempt)

            return FetchResult(False, url, reason_code=status.REASON_HTTP_ERROR)
        finally:
            spent = time.monotonic() - started
            self.run_budget.consume_seconds(spent)
            if source_budget is not None:
                source_budget.consume_seconds(spent)

    def _received(self, response, url: str, started: float, *,
                  url_guard: Callable[[str], str] | None,
                  max_content_bytes: int,
                  allowed_content_types: tuple[str, ...],
                  retry_403: bool = False) -> FetchResult | None:
        """Résultat définitif pour cette réponse, ou ``None`` pour réessayer.

        ``url_guard`` est rejoué sur **chaque** saut réellement suivi, dernier
        compris : la politique de cible reste décidée par l'appelant
        (:mod:`cyberwatch.url_safety`) tandis que politesse, robots, reprises et
        budgets restent ici — un seul gardien du réseau, contrat du module.

        Limite connue et assumée : le garde résout le DNS, puis `requests` le
        résout à son tour ; un changement d'adresse entre les deux n'est pas
        couvert. Le fermer demanderait d'épingler la socket, hors de proportion
        pour lire une page « à propos » publique.

        Rend ``None`` sur 429 et 5xx — temporaires, donc à reprendre — et sur
        403 tant que ``retry_403`` autorise l'essai sous l'agent de repli. Un
        403 au-delà est définitif et rendu en ``HTTP_403``, jamais transformé en
        erreur générique par une reprise inutile.
        """
        code = response.status_code
        elapsed = time.monotonic() - started
        final_url = str(getattr(response, "url", "") or url)

        if url_guard is not None:
            hops = [str(step.url) for step in getattr(response, "history", ())]
            if any(url_guard(hop) for hop in (*hops, final_url)):
                response.close()
                return FetchResult(False, url, code, "", status.REASON_REDIRECT_REJECTED,
                                   elapsed, {}, final_url)

        if code == 200:
            body, refusal = self._body(response, max_content_bytes, allowed_content_types)
            if refusal:
                return FetchResult(False, url, code, "", refusal, elapsed,
                                   dict(response.headers), final_url)
            return FetchResult(True, url, code, body, status.REASON_OK, elapsed,
                               dict(response.headers), final_url)

        if code == 429 or 500 <= code < 600 or (code == 403 and retry_403):
            return None

        reason = {403: status.REASON_HTTP_403,
                  404: status.REASON_HTTP_404}.get(code, status.REASON_HTTP_ERROR)
        return FetchResult(False, url, code, "", reason, elapsed)

    @staticmethod
    def _body(
        response, max_content_bytes: int, allowed_content_types: tuple[str, ...]
    ) -> tuple[str, str]:
        """Corps lu sous plafond, ou motif de refus. Jamais d'exception.

        Le plafond est appliqué **avant** d'accumuler quoi que ce soit quand le
        serveur annonce une taille, et en cours de lecture sinon : un serveur
        qui ne déclare rien ne doit pas pouvoir contourner la limite.
        """
        if allowed_content_types:
            declared = str(response.headers.get("Content-Type", "")).split(";")[0]
            if declared.strip().lower() not in allowed_content_types:
                response.close()
                return "", status.REASON_CONTENT_TYPE
        if max_content_bytes <= 0:
            return response.text, ""
        try:
            announced = int(str(response.headers.get("Content-Length", "")).strip() or -1)
        except ValueError:
            announced = -1
        if announced > max_content_bytes:
            response.close()
            return "", status.REASON_CONTENT_TOO_LARGE
        payload = bytearray()
        try:
            for chunk in response.iter_content(8192):
                payload.extend(chunk or b"")
                if len(payload) > max_content_bytes:
                    return "", status.REASON_CONTENT_TOO_LARGE
        except requests.RequestException:
            return "", status.REASON_HTTP_ERROR
        finally:
            response.close()
        encoding = response.encoding or response.apparent_encoding or "utf-8"
        try:
            return bytes(payload).decode(encoding, errors="replace"), ""
        except LookupError:
            return bytes(payload).decode("utf-8", errors="replace"), ""

    def source_budget(self) -> Budget:
        """Nouveau budget dédié à une source, dérivé des plafonds de config."""
        return Budget(
            config.MAX_REQUESTS_PER_SOURCE, config.MAX_SECONDS_PER_SOURCE, "source"
        )
