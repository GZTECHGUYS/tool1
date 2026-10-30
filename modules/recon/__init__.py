"""
modules/recon/__init__.py
─────────────────────────
Reconnaissance submodule exports.

Provides specialized recon modules for domain, subdomain, web,
CDN, cloud, social, and cache intelligence.

Compatibility note: this package sits alongside modules/recon.py, which is the
legacy public runtime entry point used by the CLI and tests. We re-export it
here so imports like 'from modules.recon import run_recon' work reliably.
"""

import importlib.util
import sys
from pathlib import Path

from modules.recon.domain import DomainRecon
from modules.recon.subdomain import SubdomainRecon
from modules.recon.web import WebRecon
from modules.recon.cdn import CDNRecon
from modules.recon.cloud import CloudRecon
from modules.recon.social import SocialRecon
from modules.recon.cache import CacheRecon
from modules.recon.adapters import DeepReconAdapterSuite

_legacy_recon_spec = importlib.util.spec_from_file_location(
    "_ardf_legacy_recon",
    Path(__file__).resolve().parent.parent / "recon.py",
)
if _legacy_recon_spec and _legacy_recon_spec.loader:
    _legacy_recon_module = importlib.util.module_from_spec(_legacy_recon_spec)
    sys.modules[_legacy_recon_spec.name] = _legacy_recon_module
    _legacy_recon_spec.loader.exec_module(_legacy_recon_module)
    run_recon = _legacy_recon_module.run_recon
else:
    def run_recon(*args, **kwargs):
        raise NotImplementedError("Legacy recon entrypoint could not be loaded")

__all__ = [
    "run_recon",
    "DomainRecon",
    "SubdomainRecon",
    "WebRecon",
    "CDNRecon",
    "CloudRecon",
    "SocialRecon",
    "CacheRecon",
    "DeepReconAdapterSuite",
]