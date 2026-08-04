# Sealed Wiki

**Tamper with the binary. The seal breaks.**

> **Scope.** `sealed install` is an *alternative* install path, not a guard on `pip`
> -- a plain `pip install` bypasses Sealed entirely. `sealed trace` (formerly
> `sealed sandbox`) is import-time *instrumentation, not containment*: do not rely
> on it to run untrusted code. The transparency log is local SQLite with no
> external witness.

## Getting Started
- [Quick Start](Quick-Start.md) - Two commands to get going
- [How It Works](How-It-Works.md) - The pipeline explained

## Guides
- [Use Cases](Use-Cases.md) - Real-world scenarios
- [Team Setup](Team-Setup.md) - Registry sharing, multi-party, key management
- [CI/CD Integration](CI-CD.md) - GitHub Actions, automated sealing
- [Code Snippets](Snippets.md) - Copy-paste Python examples

## Reference
- [CLI Reference](CLI-Reference.md) - All 14 commands (+ the deprecated `sandbox` alias)
- [Security Model](Security-Model.md) - Threat model, limitations
- [Troubleshooting](Troubleshooting.md) - Common issues and fixes
