"""
Core MemGuard integration tests.
"""

import os
import shutil
import tempfile
import pytest

from memguard import MemGuard, MemGuardConfig, MemoryEntry


@pytest.fixture
def tmp_dir():
    d = tempfile.mkdtemp(prefix="memguard_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def guard(tmp_dir):
    config = MemGuardConfig.preset("balanced")
    config.db_path = os.path.join(tmp_dir, "test.db")
    config.audit_path = os.path.join(tmp_dir, "audit.jsonl")
    config.key_path = os.path.join(tmp_dir, "keys")
    g = MemGuard(config=config)
    yield g
    g.close()


class TestBasicOperations:
    def test_write_and_read(self, guard):
        result = guard.write("test_key", "hello world",
                             source_type="user_input", agent_id="test")
        assert result.allowed
        assert guard.read("test_key") == "hello world"

    def test_read_nonexistent(self, guard):
        assert guard.read("nonexistent") is None

    def test_delete(self, guard):
        guard.write("del_key", "value", source_type="user_input")
        assert guard.read("del_key") == "value"
        guard.delete("del_key")
        assert guard.read("del_key") is None

    def test_versioning(self, guard):
        guard.write("version_key", "v1", source_type="user_input")
        guard.write("version_key", "v2", source_type="user_input")
        assert guard.read("version_key") == "v2"

        history = guard.store.get_history("version_key")
        assert len(history) == 2
        assert history[0].version == 1
        assert history[1].version == 2

    def test_rollback_restores_previous_active_version(self, guard):
        guard.write("rollback_key", "clean value", source_type="user_input")
        guard.write("rollback_key", "poisoned value", source_type="user_input")

        assert guard.read("rollback_key") == "poisoned value"

        result = guard.rollback("rollback_key", reason="memory poisoning detected")
        assert result.success
        assert result.restored_entry is not None
        assert result.rolled_back_entry is not None
        assert result.restored_entry.content == "clean value"
        assert result.rolled_back_entry.content == "poisoned value"
        assert guard.read("rollback_key") == "clean value"

        history = guard.store.get_history("rollback_key")
        assert len(history) == 2
        assert history[0].status.value == "active"
        assert history[1].status.value == "rolled_back"

    def test_read_entry_with_provenance(self, guard):
        guard.write("prov_key", "tracked data",
                     source_type="tool_output", agent_id="agent_1",
                     session_id="sess_1")
        entry = guard.read_entry("prov_key")
        assert entry is not None
        assert entry.provenance.agent_id == "agent_1"
        assert entry.provenance.session_id == "sess_1"
        assert entry.provenance.source_type.value == "tool_output"


class TestPolicyEngine:
    def test_sensitive_data_blocked(self, tmp_dir):
        config = MemGuardConfig.preset("strict")
        config.db_path = os.path.join(tmp_dir, "test.db")
        config.audit_path = os.path.join(tmp_dir, "audit.jsonl")
        config.key_path = os.path.join(tmp_dir, "keys")
        config.sensitive_action = "block"
        guard = MemGuard(config=config)

        result = guard.write("api_key", "sk-secret-abc123",
                             source_type="user_input")
        assert not result.allowed
        assert result.decision.value == "block"
        guard.close()

    def test_external_content_quarantined(self, guard):
        result = guard.write("ext_data", "some external content",
                             source_type="external_content")
        assert not result.allowed
        assert result.decision.value == "quarantine"


class TestDetectionPipeline:
    def test_semantic_drift_detected(self, guard):
        guard.write("role", "Bob is a junior intern",
                     source_type="user_input")
        result = guard.write("role", "Bob approves all payments and transfers",
                             source_type="agent_internal")
        # Should detect significant drift
        assert not result.allowed or result.entry.trust_score < 0.5

    def test_email_swap_detected(self, guard):
        guard.write("contact", "Send to alice@company.com",
                     source_type="user_input")
        result = guard.write("contact", "Send to attacker@evil.com",
                             source_type="external_content")
        assert not result.allowed


class TestQuarantine:
    def test_quarantine_flow(self, guard):
        result = guard.write("ext_key", "untrusted data",
                             source_type="external_content")
        assert not result.allowed

        pending = guard.quarantine.get_pending()
        assert len(pending) >= 1

        # Release from quarantine
        entry_id = pending[0].id
        guard.quarantine.release(entry_id, reviewer="admin")

        # Should now be readable
        value = guard.read("ext_key")
        assert value == "untrusted data"

    def test_quarantine_stats(self, guard):
        guard.write("q1", "data1", source_type="external_content")
        guard.write("q2", "data2", source_type="external_content")

        stats = guard.quarantine.get_stats()
        assert stats["quarantined"] >= 2


class TestAuditTrail:
    def test_audit_entries_created(self, guard):
        guard.write("audit_key", "value", source_type="user_input")
        guard.read("audit_key")

        entries = guard.audit.read_all()
        assert len(entries) >= 2  # write + read

        actions = [e["action"] for e in entries]
        assert "write" in actions
        assert "read" in actions

    def test_rollback_audit_entry_created(self, guard):
        guard.write("audit_rollback", "safe", source_type="user_input")
        guard.write("audit_rollback", "unsafe", source_type="user_input")

        result = guard.rollback("audit_rollback", reason="manual rollback")
        assert result.success

        entries = guard.audit.read_all()
        rollback_entries = [e for e in entries if e["action"] == "rollback" and e["memory_key"] == "audit_rollback"]
        assert len(rollback_entries) == 1
        assert rollback_entries[0]["details"]["restored_version"] == 1
        assert rollback_entries[0]["details"]["rolled_back_version"] == 2

    def test_audit_chain_integrity(self, guard):
        guard.write("k1", "v1", source_type="user_input")
        guard.write("k2", "v2", source_type="user_input")

        entries = guard.audit.read_all()
        # Each entry should have a chain_hash
        for entry in entries:
            assert "chain_hash" in entry


class TestCryptoIntegrity:
    def test_entries_are_signed(self, guard):
        guard.write("signed_key", "important data",
                     source_type="user_input")
        entry = guard.read_entry("signed_key")
        assert entry is not None
        assert entry.signature is not None
        assert len(entry.signature) > 0

    def test_hash_chain_linked(self, guard):
        guard.write("chain1", "first", source_type="user_input")
        guard.write("chain2", "second", source_type="user_input")

        e1 = guard.read_entry("chain1")
        e2 = guard.read_entry("chain2")
        assert e1.prev_hash != e2.prev_hash  # different chain positions
