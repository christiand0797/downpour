"""
CISA KEV CLIENT — fallback module for the guarded import chain (v29.60)
================================================================================
`advanced_hardware_monitor`, `backup_verifier`, `enhanced_hardware_integration`
and `system_cleanup` try `kev_checker` first, then fall back to
`cisa_kev CISAKEVClient / check_kev_status`. This module provides that
fallback by delegating to kev_checker (single implementation, both import
names work).

Never raises — all lookups degrade to {is_vulnerable: False}.
"""
from __future__ import annotations

from typing import Any, Dict, List

from kev_checker import (  # noqa: F401  (re-export parity)
    KEVChecker,
    get_kev_catalog,
    _get_checker,
    check_kev_status as _kc_status,
)


class CISAKEVClient:
    """CISA KEV client (fallback import path parity)."""

    def __init__(self, timeout: int = 15):
        self.timeout = timeout

    def get_catalog(self) -> List[Dict]:
        return get_kev_catalog()

    def check_product(self, name: str) -> Dict:
        return _get_checker().check_product(name)

    def check_hardware(self, component_type: str, name: str) -> Dict:
        return _get_checker().check_hardware(component_type, name)

    def check_file(self, filename: str) -> Dict:
        return _get_checker().check_file(filename)

    def check_kev(self, cve_id: str) -> Dict:
        return _kc_status(cve_id=cve_id)


def check_kev_status(product: str = '', cve_id: str = '') -> Dict:
    """Parity shim — see kev_checker.check_kev_status."""
    return _kc_status(product=product, cve_id=cve_id)
