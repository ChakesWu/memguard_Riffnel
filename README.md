# MemGuard_Riffnel

**State Firewall for AI Agent Memory**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/memguard-riffnel.svg)](https://pypi.org/project/memguard-riffnel/)

> Lakera protects the prompt. **MemGuard protects the state.**

---

MemGuard is a lightweight security layer for AI agent memory/state.

It helps you:
- detect suspicious updates (semantic drift, contact replacement, privilege escalation)
- quarantine or block unsafe writes
- keep safe reads returning the last known-good value
- **one-click rollback** a poisoned key to the previous safe version

## Install

```bash
pip install memguard-riffnel
```

- **Package name**: `memguard-riffnel`
- **Import name**: `memguard`

## Quickstart (dict-style)

```python
from memguard import protect

memory = protect(preset="strict")
memory["vendor_email"] = "billing@acme.com"

# suspicious write will typically be quarantined
memory.write("vendor_email", "attacker@evil.com", source_type="external_content")

# reads return the last active value
print(memory["vendor_email"])
```

## One-click rollback

Rollback marks the latest active version as `rolled_back`, and reads return the previous active version.

### Via `MemGuard`

```python
from memguard import MemGuard, MemGuardConfig

guard = MemGuard(config=MemGuardConfig.preset("balanced"))
guard.write("k", "clean", source_type="user_input")
guard.write("k", "poisoned", source_type="user_input")

r = guard.rollback("k", reason="memory poisoning detected")
print(r.success)
print(guard.read("k"))
```

### Via `SecureDict`

```python
from memguard import protect

memory = protect(preset="balanced")
memory["k"] = "clean"
memory["k"] = "poisoned"
memory.rollback("k", reason="manual rollback")
print(memory["k"])
```

## Repo examples (optional)

```bash
pip install -e .
python examples/quickstart.py
```

## Common setup issues

- **`ModuleNotFoundError: No module named 'memguard'`**
  - Make sure you installed `memguard-riffnel` into your current environment.

- **`import memguard` resolves to the wrong local module**
  - If you are inside a larger monorepo that also contains another `memguard` package, validate from a clean directory after installation.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
