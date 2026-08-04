# CLI Reference

## sealed install

Build from source, seal, verify, and install a package with all dependencies.

```bash
sealed install <package> [--version VERSION] [--no-deps]
```

| Flag | Description |
|------|-------------|
| `--version, -v` | Install specific version |
| `--no-deps` | Skip transitive dependency sealing |

> **Scope.** This is an alternative install path, not a hook on pip. Sealed builds
> and verifies the wheels itself, then calls `pip install` on those files. Running
> `pip install <package>` directly does not consult Sealed, does not check any
> seal, and can overwrite a sealed install. There is no pip plugin, PEP 517
> backend wrapper or index shim.

## sealed build

Build and seal without installing.

```bash
sealed build <package> [--version VERSION]
```

## sealed verify

Verify a sealed artifact.

```bash
sealed verify <seal.json> [--artifact FILE] [--chain FILE] [--trusted-keys FILE...]
```

| Flag | Description |
|------|-------------|
| `--artifact, -a` | Artifact file to verify hash |
| `--chain, -c` | Chain JSON file |
| `--trusted-keys, -t` | Public key files (.pub) |

## sealed inspect

Print contents of a seal or chain file.

```bash
sealed inspect <seal.json or chain.json>
```

## sealed audit

List all sealed packages with attestation method.

```bash
sealed audit
```

## sealed keygen

Generate a new Ed25519 signing key.

```bash
sealed keygen [--output FILE] [--force] [--passphrase]
```

| Flag | Description |
|------|-------------|
| `--output, -o` | Key file path (default: ~/.sealed/key.ed25519) |
| `--force, -f` | Overwrite existing key |
| `--passphrase, -p` | Encrypt with passphrase |

## sealed reproduce

Check if a package builds reproducibly.

```bash
sealed reproduce <package> [--version VERSION]
```

Builds twice from the same source, compares outputs raw and normalized.

## sealed trace

Import-time behavioral tracing. Imports a package in a child interpreter with a
CPython audit hook and Python-level wrappers, and reports what it observed.

```bash
sealed trace <package> [--version VERSION] [--timeout SECONDS]
```

| Flag | Description |
|------|-------------|
| `--timeout, -t` | Timeout in seconds (default: 30) |

> **This is observability, not containment. Do not rely on it to run untrusted
> code.** The import runs as your user with your files, network and credentials.
> `os.system`, `ctypes`, `_socket`, `os.fork`/`os.spawn*`/`os.exec*`, C extension
> module init and raw syscalls all bypass the hooks (the audit hook *records*
> some of them; nothing is prevented). Only import time is observed --
> install-time `setup.py` execution is not traced at all.

`sealed sandbox` is a deprecated alias for this command. It was never a sandbox.

## sealed provenance

Report upstream PyPI PEP 740 provenance (publisher attestations) for a release.

```bash
sealed provenance <package> [--version VERSION] [--sha256 HASH] [--json]
```

| Flag | Description |
|------|-------------|
| `--version, -v` | Release version (default: latest) |
| `--sha256` | Artifact SHA-256 to compare against the attested subject digest |
| `--json` | Machine-readable output |

Exit code is 0 when provenance exists (and any supplied digest matches), 1 when
it is absent, errored, or mismatched.

Reports the publisher identity PyPI recorded, the in-toto predicate type, subject
digests and Rekor log indexes. Sealed **parses** the Sigstore bundle; it does not
verify the signature chain, and reports `signature_verified: null` rather than
claiming verification it did not perform. Absence of provenance is common and is
not evidence of tampering.

## sealed consensus

Build N times independently, check for majority agreement.

```bash
sealed consensus <package> [--version VERSION] [--num-builds N] [--threshold FLOAT]
```

| Flag | Description |
|------|-------------|
| `--num-builds, -n` | Number of builds (default: 3) |
| `--threshold` | Agreement threshold 0.0-1.0 (default: 0.67) |

## sealed watchdog

Runtime integrity verification.

```bash
sealed watchdog check [--package NAME]
sealed watchdog list
```

| Action | Description |
|--------|-------------|
| `check` | Verify installed files against snapshots |
| `list` | List all snapshots |

## sealed trust

Trust graph with weak-link analysis.

```bash
sealed trust <package> [--version VERSION] [--json]
```

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON |

## sealed registry

Registry operations for team sharing.

```bash
sealed registry export [-o FILE]
sealed registry import [-i FILE]
sealed registry pins
sealed registry export-pins [-o FILE]
sealed registry import-pins [-i FILE]
sealed registry revoke --key KEY [--reason TEXT]
```

## sealed policy

Trust policy configuration.

```bash
sealed policy show
sealed policy set [--min-signatures N] [--tofu true/false] [--enforce-pins true/false] [--require-attestation METHOD...]
sealed policy reset
```
