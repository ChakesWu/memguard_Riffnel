"""
Policy engine — configurable rules for what can be stored in memory.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from memguard.config import MemGuardConfig
from memguard.core.memory_entry import MemoryEntry, SourceType, WriteDecision


class ViolationType(Enum):
    SENSITIVE_FIELD = "sensitive_field"
    UNTRUSTED_SOURCE = "untrusted_source"
    RATE_LIMIT = "rate_limit"
    TRUST_TOO_LOW = "trust_too_low"
    EXTERNAL_REQUIRES_REVIEW = "external_requires_review"


@dataclass
class PolicyResult:
    decision: WriteDecision
    violations: list[ViolationType]
    reasons: list[str]
    adjusted_trust: float

    @property
    def allowed(self) -> bool:
        return self.decision == WriteDecision.ALLOW


class PolicyEngine:
    """Rule-based policy engine for memory writes."""

    def __init__(self, config: MemGuardConfig):
        self._config = config
        self._write_counts: dict[str, int] = {}

    def evaluate(self, entry: MemoryEntry) -> PolicyResult:
        """Evaluate a memory write against all policies."""
        violations: list[ViolationType] = []
        reasons: list[str] = []
        trust = entry.trust_score

        # 1. Source-based trust
        trust = self._apply_source_trust(entry, trust)

        # 2. Sensitive fields
        if self._check_sensitive(entry):
            violations.append(ViolationType.SENSITIVE_FIELD)
            reasons.append(f"Content matches sensitive pattern for key '{entry.key}'")

        # 3. External content restrictions
        if entry.provenance.source_type == SourceType.EXTERNAL_CONTENT:
            trust = min(trust, self._config.external_content_max_trust)
            if self._config.external_content_require_review:
                violations.append(ViolationType.EXTERNAL_REQUIRES_REVIEW)
                reasons.append("External content requires review")

        # 4. Rate limit
        sid = entry.provenance.session_id or "__global__"
        self._write_counts[sid] = self._write_counts.get(sid, 0) + 1
        if self._write_counts[sid] > self._config.rate_limits.max_writes_per_session:
            violations.append(ViolationType.RATE_LIMIT)
            reasons.append("Session write rate limit exceeded")

        # Decision
        decision = WriteDecision.ALLOW
        if violations:
            if ViolationType.SENSITIVE_FIELD in violations:
                decision = (WriteDecision.BLOCK
                            if self._config.sensitive_action == "block"
                            else WriteDecision.QUARANTINE)
            elif ViolationType.RATE_LIMIT in violations:
                decision = WriteDecision.BLOCK
            else:
                decision = WriteDecision.QUARANTINE

        return PolicyResult(
            decision=decision,
            violations=violations,
            reasons=reasons,
            adjusted_trust=trust,
        )

    def _apply_source_trust(self, entry: MemoryEntry, trust: float) -> float:
        rules = self._config.trust_rules
        source_map = {
            SourceType.USER_INPUT: rules.user_input,
            SourceType.TOOL_OUTPUT: rules.tool_output,
            SourceType.AGENT_INTERNAL: rules.agent_internal,
            SourceType.EXTERNAL_CONTENT: rules.external_content,
            SourceType.SKILL: rules.skill,
            SourceType.SYSTEM: rules.system,
        }
        default_trust = source_map.get(entry.provenance.source_type, 0.5)
        return min(trust, default_trust)

    def _check_sensitive(self, entry: MemoryEntry) -> bool:
        key_lower = entry.key.lower()
        content_str = str(entry.content).lower()
        for pattern in self._config.sensitive_patterns:
            if pattern in key_lower or pattern in content_str:
                return True
        return False
