"""
MemGuard Memory Proxy — the core interceptor.
All memory operations route through here for security checks.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from memguard.config import MemGuardConfig
from memguard.core.audit import AuditEngine, AuditAction
from memguard.core.memory_entry import (
    MemoryEntry, MemoryStatus, Provenance, SourceType, WriteDecision,
)
from memguard.core.memory_store import MemoryStore
from memguard.core.policy_engine import PolicyEngine
from memguard.core.quarantine import QuarantineManager
from memguard.crypto.signing import Signer
from memguard.detection.pipeline import DetectionPipeline


class WriteResult:
    """Result of a memory write operation."""

    def __init__(
        self,
        allowed: bool,
        decision: WriteDecision,
        entry: Optional[MemoryEntry] = None,
        reasons: list[str] = None,
    ):
        self.allowed = allowed
        self.decision = decision
        self.entry = entry
        self.reasons = reasons or []


class RollbackResult:
    """Result of a memory rollback operation."""

    def __init__(
        self,
        success: bool,
        key: str,
        restored_entry: Optional[MemoryEntry] = None,
        rolled_back_entry: Optional[MemoryEntry] = None,
        reason: str = "",
    ):
        self.success = success
        self.key = key
        self.restored_entry = restored_entry
        self.rolled_back_entry = rolled_back_entry
        self.reason = reason


class MemGuard:
    """Main entry point — secure memory proxy.

    Usage:
        guard = MemGuard(config=MemGuardConfig.preset("balanced"))

        result = guard.write("user_email", "alice@corp.com",
            source_type="user_input", agent_id="main")

        value = guard.read("user_email")
    """

    def __init__(self, config: Optional[MemGuardConfig] = None):
        self._config = config or MemGuardConfig()
        self._config.ensure_directories()

        self._signer = (
            Signer.load_or_generate(self._config.key_path)
            if self._config.signing_enabled
            else None
        )

        self._store = MemoryStore(
            db_path=self._config.db_path, signer=self._signer,
        )
        self._audit = AuditEngine(
            audit_path=self._config.audit_path, signer=self._signer,
        )
        self._policy = PolicyEngine(self._config)
        self._detection = DetectionPipeline(self._config)
        self._quarantine = QuarantineManager(self._store, self._audit)

    def write(
        self,
        key: str,
        content: Any,
        source_type: str = "user_input",
        agent_id: str = "",
        session_id: str = "",
        channel: str = "",
        source_id: str = "",
        parent_memory_ids: Optional[list[str]] = None,
        tags: Optional[list[str]] = None,
        trust_score: Optional[float] = None,
    ) -> WriteResult:
        """Write a memory through the security pipeline.

        Pipeline: Provenance -> Policy -> Detection -> Store/Quarantine/Block
        """
        start_time = time.time()

        # Build entry with provenance
        provenance = Provenance(
            source_type=SourceType(source_type),
            source_id=source_id,
            agent_id=agent_id,
            session_id=session_id,
            channel=channel,
            parent_memory_ids=parent_memory_ids or [],
        )
        version = self._store.get_next_version(key)
        entry = MemoryEntry(
            key=key,
            content=content,
            provenance=provenance,
            trust_score=trust_score if trust_score is not None else 0.5,
            trust_decay_rate=self._config.trust_decay.rate_per_day if self._config.trust_decay.enabled else 0.0,
            version=version,
            tags=tags or [],
        )
        entry.content_hash = entry.compute_content_hash()

        # Step 1: Policy check
        policy_result = self._policy.evaluate(entry)
        entry.trust_score = policy_result.adjusted_trust

        if policy_result.decision == WriteDecision.BLOCK:
            self._audit.log(
                AuditAction.BLOCK, memory_key=key, memory_id=entry.id,
                agent_id=agent_id, session_id=session_id,
                details={"reasons": policy_result.reasons},
            )
            return WriteResult(
                allowed=False, decision=WriteDecision.BLOCK,
                entry=entry, reasons=policy_result.reasons,
            )

        # Step 2: Detection pipeline
        history = self._store.get_history(key)
        all_active = self._store.get_all_active()
        det_results = self._detection.run(entry, history, all_active)

        if DetectionPipeline.should_quarantine(det_results):
            reason = DetectionPipeline.triggered_reasons(det_results)
            entry.status = MemoryStatus.QUARANTINED
            entry.quarantine_reason = reason
            self._store.put(entry)
            self._audit.log(
                AuditAction.QUARANTINE, memory_key=key, memory_id=entry.id,
                agent_id=agent_id, session_id=session_id,
                details={"reason": reason, "detection_results": [
                    {"detector": r.detector_name, "score": r.score, "triggered": r.triggered}
                    for r in det_results
                ]},
            )
            return WriteResult(
                allowed=False, decision=WriteDecision.QUARANTINE,
                entry=entry, reasons=[reason],
            )

        # Step 3: Policy said quarantine
        if policy_result.decision == WriteDecision.QUARANTINE:
            entry.status = MemoryStatus.QUARANTINED
            entry.quarantine_reason = "; ".join(policy_result.reasons)
            self._store.put(entry)
            self._audit.log(
                AuditAction.QUARANTINE, memory_key=key, memory_id=entry.id,
                agent_id=agent_id, session_id=session_id,
                details={"reasons": policy_result.reasons},
            )
            return WriteResult(
                allowed=False, decision=WriteDecision.QUARANTINE,
                entry=entry, reasons=policy_result.reasons,
            )

        # Step 4: Allow
        entry.status = MemoryStatus.ACTIVE
        self._store.put(entry)
        self._audit.log(
            AuditAction.WRITE, memory_key=key, memory_id=entry.id,
            agent_id=agent_id, session_id=session_id,
            details={"trust": entry.trust_score, "version": entry.version},
        )
        return WriteResult(
            allowed=True, decision=WriteDecision.ALLOW, entry=entry,
        )

    def read(self, key: str, agent_id: str = "", session_id: str = "") -> Any:
        """Read a memory (only returns active, non-expired entries)."""
        entry = self._store.get(key)
        if entry is None:
            return None
        if entry.is_expired():
            self._store.update_status(entry.id, MemoryStatus.EXPIRED)
            return None
        self._audit.log(
            AuditAction.READ, memory_key=key, memory_id=entry.id,
            agent_id=agent_id, session_id=session_id,
        )
        return entry.content

    def read_entry(self, key: str, agent_id: str = "", session_id: str = "") -> Optional[MemoryEntry]:
        """Read a memory entry with full provenance."""
        entry = self._store.get(key)
        if entry is None:
            return None
        if entry.is_expired():
            self._store.update_status(entry.id, MemoryStatus.EXPIRED)
            return None
        self._audit.log(
            AuditAction.READ, memory_key=key, memory_id=entry.id,
            agent_id=agent_id, session_id=session_id,
            details={"read_type": "full_entry"},
        )
        return entry

    def delete(self, key: str, agent_id: str = "", session_id: str = "") -> bool:
        """Soft-delete a memory (preserves audit trail)."""
        entry = self._store.get(key)
        if entry is None:
            return False
        self._store.update_status(entry.id, MemoryStatus.DELETED)
        self._audit.log(
            AuditAction.DELETE, memory_key=key, memory_id=entry.id,
            agent_id=agent_id, session_id=session_id,
        )
        return True

    def rollback(self, key: str, reason: str = "", agent_id: str = "", session_id: str = "") -> RollbackResult:
        """Rollback a memory key to its previous active version."""
        rolled_back_entry, restored_entry = self._store.rollback_key(key, reason)
        if rolled_back_entry is None or restored_entry is None:
            return RollbackResult(
                success=False,
                key=key,
                reason="No previous active version available for rollback",
            )

        rollback_reason = rolled_back_entry.quarantine_reason or reason or (
            f"rolled back to version {restored_entry.version}"
        )
        self._audit.log(
            AuditAction.ROLLBACK,
            memory_key=key,
            memory_id=rolled_back_entry.id,
            agent_id=agent_id,
            session_id=session_id,
            details={
                "reason": rollback_reason,
                "rolled_back_version": rolled_back_entry.version,
                "rolled_back_entry_id": rolled_back_entry.id,
                "restored_version": restored_entry.version,
                "restored_entry_id": restored_entry.id,
            },
        )
        return RollbackResult(
            success=True,
            key=key,
            restored_entry=restored_entry,
            rolled_back_entry=rolled_back_entry,
            reason=rollback_reason,
        )

    @property
    def quarantine(self) -> QuarantineManager:
        return self._quarantine

    @property
    def store(self) -> MemoryStore:
        return self._store

    @property
    def audit(self) -> AuditEngine:
        return self._audit

    def close(self) -> None:
        """Close all resources."""
        self._store.close()
