"""
MemGuard — State Firewall for AI Agent Memory

Protects agent memory from poisoning, privilege escalation,
and semantic drift attacks. LLM-free, sub-5ms latency.

Quick start:
    from memguard import protect
    memory = protect(preset="strict")
    memory["vendor_email"] = "billing@acme.com"
"""

from importlib.metadata import PackageNotFoundError, version

_FALLBACK_VERSION = "0.1.1"

for _package_name in ("memguard-riffnel", "memguard_Riffnel"):
    try:
        __version__ = version(_package_name)
        break
    except PackageNotFoundError:
        continue
else:
    __version__ = _FALLBACK_VERSION

from memguard.core.memory_entry import MemoryEntry, Provenance, MemoryStatus
from memguard.core.memory_proxy import MemGuard
from memguard.core.quarantine import QuarantineManager
from memguard.core.audit import AuditEngine
from memguard.core.memory_store import MemoryStore
from memguard.config import MemGuardConfig
from memguard.middleware import (
    protect,
    SecureDict,
    MemGuardMiddleware,
    CallbackRegistry,
    MemGuardEvent,
)

__all__ = [
    # Core
    "MemGuard",
    "MemGuardConfig",
    "MemoryEntry",
    "Provenance",
    "MemoryStatus",
    "QuarantineManager",
    "AuditEngine",
    "MemoryStore",
    # Universal integration
    "protect",
    "SecureDict",
    "MemGuardMiddleware",
    "CallbackRegistry",
    "MemGuardEvent",
]
