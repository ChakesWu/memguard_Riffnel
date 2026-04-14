"""
MemGuard configuration — presets and YAML loading.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class TrustRules:
    """Default trust scores by source type."""
    user_input: float = 0.8
    tool_output: float = 0.6
    agent_internal: float = 0.7
    external_content: float = 0.3
    skill: float = 0.5
    system: float = 0.9


@dataclass
class TrustDecay:
    """Time-based trust decay configuration."""
    enabled: bool = True
    rate_per_day: float = 0.02


@dataclass
class RateLimits:
    """Rate limiting for memory writes."""
    max_writes_per_session: int = 100


@dataclass
class DetectionConfig:
    """Detection pipeline thresholds."""
    semantic_drift_threshold: float = 0.6
    privilege_escalation_enabled: bool = True
    contradiction_enabled: bool = True
    contradiction_similarity_threshold: float = 0.75
    fragment_assembly_enabled: bool = True
    fragment_scan_interval_writes: int = 10


@dataclass
class MemGuardConfig:
    """Main configuration for a MemGuard instance."""

    # Storage paths
    db_path: str = "./memguard_data/memories.db"
    audit_path: str = "./memguard_data/audit.jsonl"
    key_path: str = "./memguard_data/keys"

    # Signing
    signing_enabled: bool = True

    # Trust
    trust_rules: TrustRules = field(default_factory=TrustRules)
    trust_decay: TrustDecay = field(default_factory=TrustDecay)

    # Rate limits
    rate_limits: RateLimits = field(default_factory=RateLimits)

    # External content
    external_content_max_trust: float = 0.3
    external_content_require_review: bool = True

    # Sensitive data handling
    sensitive_patterns: list[str] = field(default_factory=lambda: [
        "password", "api_key", "secret", "token", "credit_card",
        "ssn", "private_key",
    ])
    sensitive_action: str = "quarantine"  # "block" or "quarantine"

    # Detection
    detection: DetectionConfig = field(default_factory=DetectionConfig)

    def ensure_directories(self) -> None:
        """Create data directories if they don't exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.audit_path).parent.mkdir(parents=True, exist_ok=True)
        if self.signing_enabled:
            Path(self.key_path).mkdir(parents=True, exist_ok=True)

    @classmethod
    def preset(cls, name: str) -> MemGuardConfig:
        """Load a preset configuration.

        Available presets:
        - "strict": aggressive detection, low trust defaults
        - "balanced": recommended for most use cases
        - "permissive": minimal blocking, for development/testing
        """
        if name == "strict":
            return cls(
                trust_rules=TrustRules(
                    user_input=0.7, tool_output=0.4,
                    agent_internal=0.5, external_content=0.1,
                    skill=0.3, system=0.9,
                ),
                trust_decay=TrustDecay(enabled=True, rate_per_day=0.05),
                external_content_max_trust=0.1,
                external_content_require_review=True,
                sensitive_action="block",
                detection=DetectionConfig(
                    semantic_drift_threshold=0.4,
                    fragment_scan_interval_writes=5,
                ),
            )
        elif name == "permissive":
            return cls(
                trust_rules=TrustRules(
                    user_input=0.9, tool_output=0.8,
                    agent_internal=0.8, external_content=0.5,
                    skill=0.7, system=1.0,
                ),
                trust_decay=TrustDecay(enabled=False, rate_per_day=0.0),
                external_content_max_trust=0.5,
                external_content_require_review=False,
                sensitive_action="quarantine",
                detection=DetectionConfig(
                    semantic_drift_threshold=0.8,
                    fragment_scan_interval_writes=20,
                ),
            )
        else:  # balanced (default)
            return cls()

    @classmethod
    def from_yaml(cls, path: str) -> MemGuardConfig:
        """Load configuration from a YAML file."""
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> MemGuardConfig:
        cfg = cls()
        for k, v in data.items():
            if k == "trust_rules" and isinstance(v, dict):
                cfg.trust_rules = TrustRules(**v)
            elif k == "trust_decay" and isinstance(v, dict):
                cfg.trust_decay = TrustDecay(**v)
            elif k == "rate_limits" and isinstance(v, dict):
                cfg.rate_limits = RateLimits(**v)
            elif k == "detection" and isinstance(v, dict):
                cfg.detection = DetectionConfig(**v)
            elif hasattr(cfg, k):
                setattr(cfg, k, v)
        return cfg
