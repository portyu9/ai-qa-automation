"""Independent external Trusted PR Gate admission service.

This package is reference/deployment source only. Repository presence does not grant merge authority;
terminal authority exists only when an independently administered deployment is pinned, configured,
and observed publishing through the dedicated Trusted PR Gate GitHub App.
"""

from .core import OneShotPolicy, ProtectedTransition, Subject
from .service import DeliveryResult, ServiceConfig, TrustedGateService

__all__ = [
    "DeliveryResult",
    "OneShotPolicy",
    "ProtectedTransition",
    "ServiceConfig",
    "Subject",
    "TrustedGateService",
]
