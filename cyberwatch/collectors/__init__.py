"""Collecteurs : chaque source déclare lequel utiliser via `SourceSpec.collector`."""

from __future__ import annotations

from .autodetect import AutodetectCollector
from .base import CollectResult, Collector, RawEntry, SourceSpec, Window
from .feed import FeedCollector
from .jsonld import JsonLdCollector
from .mediawatch import MediaWatchCollector
from .newsrss import NewsRssCollector
from .ransomware_live import RansomwareLiveCollector
from .wordpress import WordPressCollector

REGISTRY: dict[str, type[Collector]] = {
    "autodetect": AutodetectCollector,
    "wordpress": WordPressCollector,
    "feed": FeedCollector,
    "jsonld": JsonLdCollector,
    "newsrss": NewsRssCollector,
    "mediawatch": MediaWatchCollector,
    "ransomware_live": RansomwareLiveCollector,
}


def get_collector(name: str) -> Collector:
    """Instancie le collecteur déclaré par une source."""
    collector_class = REGISTRY.get(name, AutodetectCollector)
    return collector_class()


__all__ = [
    "REGISTRY",
    "get_collector",
    "Collector",
    "CollectResult",
    "RawEntry",
    "SourceSpec",
    "Window",
]
