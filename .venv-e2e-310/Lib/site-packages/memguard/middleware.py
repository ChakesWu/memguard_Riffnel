"""
Universal integration layer — adapt MemGuard to ANY memory backend.

Three integration patterns for different enterprise environments:

1. protect()       — one-liner, wraps any dict-like object
2. SecureDict      — dict-compatible drop-in replacement
3. MemGuardMiddleware — wrap any backend with custom read/write functions

All patterns provide: detection, quarantine, audit, cryptographic integrity.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Optional

from memguard.config import MemGuardConfig
from memguard.core.memory_proxy import MemGuard, WriteResult
from memguard.core.memory_entry import WriteDecision


# ─── Callback Types ──────────────────────────────────────────────────────────

class MemGuardEvent:
    """Event emitted on every memory operation."""

    def __init__(
        self,
        action: str,        # "allow", "quarantine", "block", "read"
        key: str,
        content: Any = None,
        reasons: list[str] = None,
        latency_ms: float = 0.0,
        entry: Any = None,
    ):
        self.action = action
        self.key = key
        self.content = content
        self.reasons = reasons or []
        self.latency_ms = latency_ms
        self.entry = entry
        self.timestamp = time.time()


# Callback signature: fn(event: MemGuardEvent) -> None
EventCallback = Callable[[MemGuardEvent], None]


class CallbackRegistry:
    """Register callbacks for MemGuard events.

    Usage:
        guard = MemGuard()
        callbacks = CallbackRegistry()
        callbacks.on_quarantine(lambda e: slack.post(f"Quarantined: {e.key}"))
        callbacks.on_block(lambda e: pagerduty.alert(f"Blocked: {e.key}"))
    """

    def __init__(self):
        self._on_allow: list[EventCallback] = []
        self._on_quarantine: list[EventCallback] = []
        self._on_block: list[EventCallback] = []
        self._on_read: list[EventCallback] = []

    def on_allow(self, fn: EventCallback) -> None:
        """Called when a write is allowed."""
        self._on_allow.append(fn)

    def on_quarantine(self, fn: EventCallback) -> None:
        """Called when a write is quarantined."""
        self._on_quarantine.append(fn)

    def on_block(self, fn: EventCallback) -> None:
        """Called when a write is blocked."""
        self._on_block.append(fn)

    def on_read(self, fn: EventCallback) -> None:
        """Called on every read."""
        self._on_read.append(fn)

    def _emit(self, event: MemGuardEvent) -> None:
        handlers = {
            "allow": self._on_allow,
            "quarantine": self._on_quarantine,
            "block": self._on_block,
            "read": self._on_read,
        }
        for fn in handlers.get(event.action, []):
            try:
                fn(event)
            except Exception:
                pass  # callbacks must not break the pipeline


# ─── SecureDict — dict-compatible drop-in ─────────────────────────────────

class SecureDict:
    """Dict-compatible memory store with MemGuard protection.

    Works as a drop-in replacement for any dict-based memory system.
    Every __setitem__ goes through the full security pipeline.
    Every __getitem__ returns only active, non-quarantined values.

    Usage:
        # Replace:  memory = {}
        # With:     memory = SecureDict()
        memory = SecureDict(preset="strict")

        memory["vendor_email"] = "billing@acme.com"     # → guard.write()
        email = memory["vendor_email"]                   # → guard.read()
        del memory["vendor_email"]                       # → guard.delete()
        "vendor_email" in memory                         # → True/False
    """

    def __init__(
        self,
        guard: Optional[MemGuard] = None,
        config: Optional[MemGuardConfig] = None,
        preset: str = "balanced",
        agent_id: str = "",
        session_id: str = "",
        source_type: str = "agent_internal",
        callbacks: Optional[CallbackRegistry] = None,
    ):
        if guard:
            self._guard = guard
        elif config:
            self._guard = MemGuard(config=config)
        else:
            self._guard = MemGuard(config=MemGuardConfig.preset(preset))

        self._agent_id = agent_id
        self._session_id = session_id
        self._source_type = source_type
        self._callbacks = callbacks or CallbackRegistry()
        self._last_result: Optional[WriteResult] = None

    @property
    def guard(self) -> MemGuard:
        return self._guard

    @property
    def callbacks(self) -> CallbackRegistry:
        return self._callbacks

    @property
    def last_result(self) -> Optional[WriteResult]:
        """Get the WriteResult from the last __setitem__ call."""
        return self._last_result

    def write(
        self,
        key: str,
        value: Any,
        source_type: Optional[str] = None,
        agent_id: Optional[str] = None,
        **kwargs,
    ) -> WriteResult:
        """Explicit write with full control over parameters."""
        t0 = time.time()
        result = self._guard.write(
            key=key,
            content=value,
            source_type=source_type or self._source_type,
            agent_id=agent_id or self._agent_id,
            session_id=self._session_id,
            **kwargs,
        )
        latency = (time.time() - t0) * 1000
        self._last_result = result

        action = result.decision.value
        event = MemGuardEvent(
            action=action, key=key, content=value,
            reasons=result.reasons, latency_ms=latency, entry=result.entry,
        )
        self._callbacks._emit(event)
        return result

    def __setitem__(self, key: str, value: Any) -> None:
        """Dict-style write — goes through MemGuard pipeline."""
        self.write(key, value)

    def __getitem__(self, key: str) -> Any:
        """Dict-style read — returns only active, safe values."""
        t0 = time.time()
        value = self._guard.read(key, agent_id=self._agent_id, session_id=self._session_id)
        latency = (time.time() - t0) * 1000
        if value is None:
            raise KeyError(key)
        self._callbacks._emit(MemGuardEvent(
            action="read", key=key, content=value, latency_ms=latency,
        ))
        return value

    def get(self, key: str, default: Any = None) -> Any:
        """Dict-style get with default."""
        value = self._guard.read(key, agent_id=self._agent_id, session_id=self._session_id)
        return value if value is not None else default

    def __delitem__(self, key: str) -> None:
        """Dict-style delete (soft-delete, preserves audit trail)."""
        self._guard.delete(key, agent_id=self._agent_id, session_id=self._session_id)

    def __contains__(self, key: str) -> bool:
        return self._guard.read(key) is not None

    def __len__(self) -> int:
        return self._guard.store.count_active()

    def close(self) -> None:
        self._guard.close()


# ─── MemGuardMiddleware — wrap any backend ────────────────────────────────

class MemGuardMiddleware:
    """Wrap ANY memory backend with MemGuard protection.

    You provide the original read/write functions, and MemGuard intercepts
    all operations transparently. The original backend is only written to
    if MemGuard allows the write.

    Usage:
        import redis
        r = redis.Redis()

        mw = MemGuardMiddleware(
            write_fn=lambda k, v: r.set(k, v),
            read_fn=lambda k: r.get(k),
            delete_fn=lambda k: r.delete(k),
            preset="strict",
        )

        mw.write("vendor_email", "billing@acme.com")  # checks + writes to Redis
        email = mw.read("vendor_email")                # reads from MemGuard
    """

    def __init__(
        self,
        write_fn: Callable[[str, Any], Any],
        read_fn: Optional[Callable[[str], Any]] = None,
        delete_fn: Optional[Callable[[str], Any]] = None,
        guard: Optional[MemGuard] = None,
        config: Optional[MemGuardConfig] = None,
        preset: str = "balanced",
        agent_id: str = "",
        session_id: str = "",
        source_type: str = "agent_internal",
        callbacks: Optional[CallbackRegistry] = None,
    ):
        if guard:
            self._guard = guard
        elif config:
            self._guard = MemGuard(config=config)
        else:
            self._guard = MemGuard(config=MemGuardConfig.preset(preset))

        self._write_fn = write_fn
        self._read_fn = read_fn
        self._delete_fn = delete_fn
        self._agent_id = agent_id
        self._session_id = session_id
        self._source_type = source_type
        self._callbacks = callbacks or CallbackRegistry()

    @property
    def guard(self) -> MemGuard:
        return self._guard

    @property
    def callbacks(self) -> CallbackRegistry:
        return self._callbacks

    def write(
        self,
        key: str,
        value: Any,
        source_type: Optional[str] = None,
        agent_id: Optional[str] = None,
        **kwargs,
    ) -> WriteResult:
        """Write through MemGuard, then to the real backend if allowed."""
        t0 = time.time()
        result = self._guard.write(
            key=key,
            content=value,
            source_type=source_type or self._source_type,
            agent_id=agent_id or self._agent_id,
            session_id=self._session_id,
            **kwargs,
        )
        latency = (time.time() - t0) * 1000

        if result.allowed:
            self._write_fn(key, value)

        event = MemGuardEvent(
            action=result.decision.value, key=key, content=value,
            reasons=result.reasons, latency_ms=latency, entry=result.entry,
        )
        self._callbacks._emit(event)
        return result

    def read(self, key: str) -> Any:
        """Read from MemGuard (returns only safe, non-quarantined values)."""
        value = self._guard.read(key, agent_id=self._agent_id, session_id=self._session_id)
        self._callbacks._emit(MemGuardEvent(action="read", key=key, content=value))
        return value

    def delete(self, key: str) -> bool:
        """Delete through MemGuard, then from the real backend."""
        success = self._guard.delete(key, agent_id=self._agent_id, session_id=self._session_id)
        if success and self._delete_fn:
            self._delete_fn(key)
        return success

    def close(self) -> None:
        self._guard.close()


# ─── protect() — one-liner ────────────────────────────────────────────────

def protect(
    backend: Any = None,
    preset: str = "balanced",
    config: Optional[MemGuardConfig] = None,
    agent_id: str = "",
    session_id: str = "",
    callbacks: Optional[CallbackRegistry] = None,
) -> SecureDict:
    """One-liner to protect any dict-like memory backend.

    Usage:
        from memguard import protect

        # Protect a new memory store
        memory = protect(preset="strict")
        memory["vendor_email"] = "alice@acme.com"

        # Protect an existing dict (copies existing values)
        existing = {"user": "alice", "role": "admin"}
        memory = protect(existing, preset="balanced")

    Args:
        backend: Optional dict-like object to copy initial values from.
        preset: Config preset ("strict", "balanced", "permissive").
        config: Full MemGuardConfig (overrides preset if provided).
        agent_id: Agent identifier for audit trail.
        session_id: Session identifier for audit trail.
        callbacks: Optional CallbackRegistry for event hooks.

    Returns:
        SecureDict with MemGuard protection.
    """
    cfg = config or MemGuardConfig.preset(preset)
    sd = SecureDict(
        config=cfg,
        agent_id=agent_id,
        session_id=session_id,
        callbacks=callbacks or CallbackRegistry(),
    )

    # Copy existing values if provided
    if backend and hasattr(backend, "items"):
        for key, value in backend.items():
            sd.write(key, value, source_type="system")

    return sd
