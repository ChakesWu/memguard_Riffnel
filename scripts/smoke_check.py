from pathlib import Path
import tempfile

import memguard
from memguard import MemGuardConfig, protect


def main() -> None:
    data_dir = Path(tempfile.mkdtemp(prefix="memguard_smoke_"))
    config = MemGuardConfig.preset("strict")
    config.db_path = str(data_dir / "memories.db")
    config.audit_path = str(data_dir / "audit.jsonl")
    config.key_path = str(data_dir / "keys")

    memory = protect(config=config)
    memory["vendor_email"] = "billing@acme.com"
    result = memory.write(
        "vendor_email",
        "attacker@evil.com",
        source_type="external_content",
    )
    safe_value = memory.get("vendor_email")
    memory.close()

    if not memguard.__version__:
        raise SystemExit("Missing package version")
    if result.allowed:
        raise SystemExit("Expected malicious replacement to be quarantined")
    if safe_value != "billing@acme.com":
        raise SystemExit(f"Unexpected safe value: {safe_value!r}")

    print("smoke_ok")
    print(memguard.__version__)
    print(safe_value)


if __name__ == "__main__":
    main()
