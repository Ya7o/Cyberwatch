"""Cyberwatch — observatoire des incidents cyber France / Océan Indien.

Implémentation exécutable de la méthodologie OBS-FR-OI : collecte multi-sources,
base déterministe reproductible, et dashboard statique publié sur GitHub Pages.
"""

from .config import METHOD_ID
from .sector_completion import install as _install_sector_completion

_install_sector_completion()

__all__ = ["METHOD_ID"]
__version__ = "1.0.0"
