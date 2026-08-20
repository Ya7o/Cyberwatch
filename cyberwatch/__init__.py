"""Cyberwatch — observatoire des incidents cyber France / Océan Indien.

Implémentation exécutable de la méthodologie OBS-FR-OI : collecte multi-sources,
base déterministe reproductible, et dashboard statique publié sur GitHub Pages.
"""

from .config import METHOD_ID
from .sector_completion import install as _install_sector_completion
from .incremental_performance import install as _install_incremental_performance
from .incremental_performance_contract import install as _install_incremental_performance_contract
from .incremental_runtime import install as _install_incremental_runtime
from .performance_closeout import install as _install_performance_closeout

_install_sector_completion()
_install_incremental_performance()
_install_incremental_performance_contract()
_install_incremental_runtime()
_install_performance_closeout()

__all__ = ["METHOD_ID"]
__version__ = "1.0.0"
