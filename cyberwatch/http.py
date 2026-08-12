"""Couche HTTP : politesse, reprises, robots.txt et plafonds durs.

Cette couche est le garde-fou de volumétrie du projet. Aucun collecteur ne fait
d'appel réseau directement : tous passent par `HttpClient`, ce qui garantit que
les plafonds de `config` s'appliquent partout, sans exception possible.
"""

from __future__ import annotations

import time
import urllib.robotparser
from dataclasses import dataclass, field
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

    def json(self):
        """Corps interprété en JSON, ou `None` si le corps n'en est pas."""
        import json

        try:
            return json.loads(self.text)
        except (ValueError, TypeError):
            return None


class Budget:
    """Compteur de requêtes et de temps, avec plafonds durs.

    Un budget épuisé n'interrompt jamais brutalement le run : le collecteur en
    cours s'arrête proprement et la source est marquée `PARTIAL` avec sa
    couverture réelle. Les données déjà collectées sont conservées.
    """

    def __init__(self, max_requests: int, max_seconds: float, label: str = ""):
        self.max_requests = max_requests
        self.max_seconds = max_seconds
        self.label = label
        self.requests_made = 0
        self.started_at = time.monotonic()

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started_at

    @property
    def exhausted(self) -> bool:
        return (
            self.requests_made >= self.max_requests
            or self.elapsed >= self.max_seconds
        )

    def remaining_requests(self) -> int:
        return max(0, self.max_requests - self.requests_made)

    def consume(self, count: int = 1) -> None:
        self.requests_made += count

    def reset_clock(self) -> None:
        self.started_at = time.monotonic()


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
    ):
        self.run_budget = run_budget or Budget(
            config.MAX_REQUESTS_PER_RUN, config.MAX_SECONDS_PER_RUN, "run"
        )
        self.polite_delay = polite_delay
        self.timeout = timeout
        self.respect_robots = respect_robots

        self.session = requests.Session()
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
    ) -> FetchResult:
        """Récupère une URL en respectant tous les plafonds.

        Ne lève jamais d'exception réseau : chaque échec devient un
        `FetchResult` porteur d'un code de raison exploitable par le modèle de
        statuts.
        """
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
                    url, timeout=self.timeout, headers=request_headers
                )
            except requests.Timeout:
                attempt += 1
                if attempt > config.HTTP_MAX_RETRIES:
                    return FetchResult(
                        False, url, reason_code=status.REASON_TIMEOUT,
                        elapsed=time.monotonic() - started,
                    )
                time.sleep(2 ** attempt)
                continue
            except requests.RequestException:
                attempt += 1
                if attempt > config.HTTP_MAX_RETRIES:
                    return FetchResult(
                        False, url, reason_code=status.REASON_HTTP_ERROR,
                        elapsed=time.monotonic() - started,
                    )
                time.sleep(2 ** attempt)
                continue

            code = response.status_code
            elapsed = time.monotonic() - started

            if code == 200:
                return FetchResult(
                    True, url, code, response.text, status.REASON_OK, elapsed,
                    dict(response.headers),
                )

            # 429 et 5xx : temporaires, on retente avec un recul croissant.
            if code == 429 or 500 <= code < 600:
                attempt += 1
                if attempt > config.HTTP_MAX_RETRIES:
                    reason = (
                        status.REASON_HTTP_429 if code == 429
                        else status.REASON_HTTP_ERROR
                    )
                    return FetchResult(False, url, code, "", reason, elapsed)
                time.sleep(2 ** attempt)
                continue

            # 403 alors que le robots.txt autorise le chemin : le refus vient
            # d'un pare-feu qui filtre sur l'agent, pas d'une politique
            # d'exclusion. On réessaie une fois en se présentant sous une forme
            # que ces pare-feux acceptent, sans masquer l'identité du projet.
            if code == 403 and not tried_fallback_ua and host not in self._fallback_hosts:
                tried_fallback_ua = True
                self._fallback_hosts.add(host)
                continue

            reason = {
                403: status.REASON_HTTP_403,
                404: status.REASON_HTTP_404,
            }.get(code, status.REASON_HTTP_ERROR)
            return FetchResult(False, url, code, "", reason, elapsed)

        return FetchResult(False, url, reason_code=status.REASON_HTTP_ERROR)

    def source_budget(self) -> Budget:
        """Nouveau budget dédié à une source, dérivé des plafonds de config."""
        return Budget(
            config.MAX_REQUESTS_PER_SOURCE, config.MAX_SECONDS_PER_SOURCE, "source"
        )
