"""
Format handler registry.

Imports all handlers and provides a registry for the detector to iterate over.
"""

from .android_ab import AndroidABHandler
from .miui_lsa import MIUILSAHandler
from .miui_bak import MIUIBakHandler
from .huawei import HuaweiHandler
from .seedvault import SeedvaultHandler
from .whatsapp import WhatsAppHandler
from .twrp import TWRPHandler

# Ordered by detection priority — most common / most distinct magic bytes first
HANDLER_REGISTRY = [
    AndroidABHandler,
    TWRPHandler,
    MIUILSAHandler,
    MIUIBakHandler,
    HuaweiHandler,
    SeedvaultHandler,
    WhatsAppHandler,
]

__all__ = [
    "AndroidABHandler",
    "MIUILSAHandler",
    "MIUIBakHandler",
    "HuaweiHandler",
    "SeedvaultHandler",
    "WhatsAppHandler",
    "TWRPHandler",
    "HANDLER_REGISTRY",
]
