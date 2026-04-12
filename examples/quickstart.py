"""
MemGuard Quick Start — 5 minutes to secure agent memory.

Run:
    pip install memguard
    python examples/quickstart.py
"""

from memguard import MemGuard, MemGuardConfig

# Initialize with balanced preset
guard = MemGuard(config=MemGuardConfig.preset("balanced"))

# --- Normal operations ---

# Write a trusted memory
result = guard.write(
    "user_preference",
    "dark mode enabled",
    source_type="user_input",
    agent_id="settings_agent",
)
print(f"Write allowed: {result.allowed}")  # True

# Read it back
value = guard.read("user_preference")
print(f"Read value: {value}")  # "dark mode enabled"

# --- Security in action ---

# Write initial vendor info
guard.write("vendor_email", "payments@acme-corp.com",
            source_type="user_input", agent_id="procurement")

# Try to replace with suspicious email — quarantined
result = guard.write("vendor_email", "payments@attacker-evil.com",
                     source_type="external_content", agent_id="procurement")
print(f"\nSuspicious write allowed: {result.allowed}")  # False
print(f"Decision: {result.decision}")  # QUARANTINE
print(f"Reasons: {result.reasons}")

# Original value is still intact
safe_value = guard.read("vendor_email")
print(f"Safe value: {safe_value}")  # "payments@acme-corp.com"

# --- Quarantine management ---

pending = guard.quarantine.get_pending()
print(f"\nQuarantined entries: {len(pending)}")
for entry in pending:
    print(f"  - {entry.key}: {entry.quarantine_reason}")

# --- Audit trail ---

audit_entries = guard.audit.read_all()
print(f"\nAudit entries: {len(audit_entries)}")
for entry in audit_entries[-3:]:
    print(f"  [{entry['action']}] {entry['memory_key']} @ {entry['timestamp'][:19]}")

# Cleanup
guard.close()
print("\nDone.")
