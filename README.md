<p align="center">
  <img src="assets/logo.png" alt="Sealed" width="280">
  <br><br>
  <b>Tamper with the binary. The seal breaks.</b>
  <br><br>
  <a href="https://pypi.org/project/alia-sealed/"><img src="https://img.shields.io/pypi/v/alia-sealed?color=green" alt="PyPI"></a>
  <a href="https://github.com/TxsharDev/Sealed/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-green" alt="License"></a>
  <a href="https://github.com/TxsharDev/Sealed/actions"><img src="https://img.shields.io/badge/tests-passing-green" alt="Tests"></a>
  <br><br>
  <a href="docs/wiki/Home.md">Wiki</a> &nbsp;|&nbsp;
  <a href="docs/wiki/Quick-Start.md">Quick Start</a> &nbsp;|&nbsp;
  <a href="docs/wiki/Use-Cases.md">Use Cases</a> &nbsp;|&nbsp;
  <a href="docs/wiki/Snippets.md">Snippets</a> &nbsp;|&nbsp;
  <a href="docs/wiki/CLI-Reference.md">CLI Reference</a> &nbsp;|&nbsp;
  <a href="docs/wiki/Security-Model.md">Security</a>
</p>

---

Every dependency you install is a trust decision you didn't make. Someone compiled that binary. You hope it matches the source. You have no proof.

Sealed fixes that. One command:

```bash
sealed install requests
```

What just happened:

1. Resolved every transitive dependency
2. Downloaded source from PyPI (not wheels, actual source)
3. Scanned source for dangerous patterns, CVEs, and install-time code execution
4. Looked up upstream PyPI provenance (PEP 740) and recorded whether the publisher attested this exact file
5. Measured the build environment (Python, compiler, OS, CPU, env vars)
6. Built each from source
7. Signed provenance chains with Ed25519
8. Checked trust policy (TOFU key pinning, revocation, multi-party)
9. Logged to a local append-only transparency chain
10. Installed the verified artifacts by calling pip on them

If anyone tampered with anything at any step, the seal doesn't verify. You know before the code runs.

### Scope, up front

Three things Sealed is **not**, so you don't have to find out later:

- **`sealed install` is an alternative install path, not a guard on pip.** It builds, seals, verifies, then shells out to `pip install` on the wheels it produced. A plain `pip install <pkg>` in the same environment never consults Sealed. There is no pip plugin, no PEP 517 backend wrapper, no index shim. If you want the guarantee, you have to use `sealed install`.
- **`sealed trace` is instrumentation, not a sandbox.** It observes what a package does at import; it does not contain it. See [Import-time tracing](#import-time-tracing-not-a-sandbox).
- **Your seal is self-signed and the transparency log is local.** Sealed signs with *your* key and appends to a SQLite hash chain on *your* disk, with no external witness. Anyone who can write `~/.sealed` can rebuild that chain. The only externally anchored trust signal Sealed consumes is upstream PyPI PEP 740 provenance (`sealed provenance`).

## Install

```bash
pip install alia-sealed
```

No config. No setup. First run generates your signing key (encrypted, or stored in OS keychain).

## Usage

```bash
# Install with full supply chain attestation
sealed install requests

# Install specific version, skip dep sealing
sealed install flask --version 3.1.0 --no-deps

# Build and seal without installing
sealed build numpy

# Verify a seal
sealed verify ~/.sealed/store/requests-2.32.3/seal.json \
  --artifact ~/.sealed/store/requests-2.32.3/requests-2.32.3-py3-none-any.whl

# Inspect provenance chain
sealed inspect ~/.sealed/store/requests-2.32.3/chain.json

# List all sealed packages
sealed audit
```

### Security Analysis

```bash
# Import-time behavioral trace: observe (NOT contain) what a package does at import
sealed trace suspicious-package

# Upstream publisher provenance (PEP 740) for a release
sealed provenance requests
sealed provenance sigstore --version 4.4.0 --sha256 <sdist-sha256>

# Consensus build: build 3 times, check agreement
sealed consensus requests --num-builds 3

# Reproducibility check: build twice, compare
sealed reproduce flask

# Runtime integrity: check for post-install tampering
sealed watchdog check

# Trust graph: see your dependency tree with trust scores
sealed trust requests
```

### Team Sharing

```bash
# Export/import seals
sealed registry export -o team-seals.json
sealed registry import -i team-seals.json

# Export/import key pins
sealed registry export-pins -o pins.json
sealed registry import-pins -i pins.json

# Revoke a compromised key
sealed registry revoke --key <hex-public-key> --reason "compromised"
```

### Trust Policy

```bash
# Require 2+ independent signers
sealed policy set --min-signatures 2

# Require TPM attestation
sealed policy set --require-attestation tpm2

# Disable TOFU (manual key pinning only)
sealed policy set --tofu false
```

## What Makes This Different

| Tool | What It Does | Sealed's Angle |
|------|-------------|----------------|
| **Sigstore** | Keyless signing via OIDC, Rekor transparency log | Local-first signing; Sealed *consumes* PyPI's Sigstore-backed PEP 740 provenance but does not verify the signature chain. Its own log has no external witness. |
| **in-toto** | Multi-party supply chain layout verification | Single command. No layout files. |
| **SLSA** | Framework for supply chain security levels | SLSA is a spec. Sealed is a tool. |
| **TUF** | Secure software update delivery | TUF secures distribution. Sealed secures the build. |
| **Nix/Guix** | Deterministic reproducible package managers | Sealed wraps your existing pip workflow. |

Zero-config, single-command, full-stack. Two commands to start:

```
pip install alia-sealed
sealed install <package>
```

## Architecture

```
sealed/
  chain.py           Provenance chain (SHA-256 hashing, environment fingerprinting)
  source.py          PyPI source fetcher (rejects wheels, verifies hashes)
  builder.py         Isolated builder with attestation and source audit
  attestation.py     Software attestation + TPM 2.0 (when available)
  audit_source.py    Source scanner (patterns, CVEs, setup.py analysis)
  seal.py            Ed25519 signing authority
  verify.py          End-to-end verifier
  resolver.py        Recursive dependency resolver (topological ordering)
  registry.py        SQLite seal store (TOFU key pinning, export/import)
  policy.py          Trust policy engine (multi-party, attestation, revocation)
  keystore.py        Encrypted key storage (PBKDF2 + NaCl SecretBox)
  reproduce.py       Reproducibility checker (build twice, compare)
  tracer.py          Import-time behavioral tracing (observability, no containment)
  sandbox.py         Deprecated shim re-exporting tracer.py under the old names
  provenance.py      Upstream PyPI PEP 740 provenance lookup (publisher attestations)
  consensus.py       Consensus builds (N builds, majority vote)
  watchdog.py        Runtime integrity watchdog (post-install hash check)
  trust_graph.py     Trust graph with scored weak-link analysis
  transparency.py    Append-only hash-chained transparency log
  ecosystem.py       Multi-ecosystem adapters (pip, npm, cargo)
  os_keychain.py     OS keychain (Windows DPAPI, macOS Keychain, Linux libsecret)
  lockfile.py        Lockfile for reproducible team installs
  cli.py             14 CLI commands (+ `sandbox`, deprecated alias of `trace`)
```

## Import-time tracing (not a sandbox)

`sealed trace <pkg>` imports a package in a child interpreter with a CPython
audit hook (`sys.addaudithook`) plus Python-level wrappers around `socket`,
`subprocess.Popen`, `open` and `os.getenv`, and reports what it saw.

**This is observability, not containment. Do not rely on it to run untrusted
code.** The traced import runs as your user, with your filesystem, your network
and your credentials. Nothing is dropped, jailed, or namespaced.

Documented bypasses — all of these execute regardless of what the trace prints:

| Bypass | What happens |
|--------|--------------|
| `os.system` / `os.popen` | No `Popen` wrapper is involved. The audit hook records it; the command still runs. |
| `ctypes` / `cffi` | `ctypes.CDLL(...)` / `ctypes.windll` call native code. Visible at `dlopen` at best; individual calls are invisible. |
| `_socket` | The C accelerator under `socket`. Rebinding `socket.socket` in Python does not touch it. |
| `os.fork` / `os.spawn*` / `os.exec*` | The child interpreter starts clean, with none of these hooks. |
| C extension module init | Runs below the Python layer before any hook can observe it. |
| Raw syscalls | Emit no audit event at all. |

Scope limit: it only observes **import time**. The bigger supply-chain risk —
`setup.py` executing at *install* time — is not traced here; it is statically
regex-scanned by `audit_source.py`, which is pattern matching, not execution.

If you need actual isolation, run the package in a disposable VM or container
with no network and no credentials. Sealed does not provide one, and
`sealed trace` is not a substitute.

## Upstream provenance (PEP 740)

Sealed's own seals are self-signed: signing your own build with your own TOFU-pinned
key proves your machine produced that binary from that source. It says nothing about
whether the source came from the real publisher.

`sealed provenance <pkg>` reads PyPI's Integrity API
(`https://pypi.org/integrity/{name}/{version}/{file}/provenance`) and reports:

- whether a PEP 740 attestation bundle exists at all,
- the publisher identity PyPI recorded (e.g. `GitHub / sigstore/sigstore-python / release.yml`),
- the in-toto predicate type and subject SHA-256,
- Rekor transparency-log indexes,
- whether the attested subject digest equals the artifact hash you supply (`--sha256`).

`sealed install` and `sealed build` run the same lookup and record the result as an
`upstream_provenance` step in the signed provenance chain, so absence or presence is
part of what gets signed.

What this does **not** do: Sealed parses the Sigstore bundle, it does not verify the
signature chain. `signature_verified` is reported as `null`, never as `true`, so the
output cannot be mistaken for cryptographic verification. Absence of provenance is
also normal — most PyPI projects still upload with API tokens — and is reported as
absence, not as tampering.

## Provenance Chain

Every sealed package carries a 5-step chain:

| Step | What It Records | What It Proves |
|------|----------------|----------------|
| `environment_attestation` | Python, compiler, OS, CPU, env vars, TPM PCRs | Build machine state is known |
| `source_audit` | Pattern scan + CVE check + setup.py analysis | Source was scanned for known dangers |
| `source_verify` | Archive hash vs PyPI registry hash | Source wasn't modified after download |
| `toolchain_capture` | Python interpreter hash | Exact compiler that built the artifact |
| `build` | Source dir hash in, artifact hash out | Binary came from this exact source |

Environment, all records, and package identity are hashed into the chain. Signed with Ed25519. One bit changed = signature fails = rejected.

## Security Model

**What Sealed catches:**

| Threat | How |
|--------|-----|
| Mirror tampering | SHA-256 fail-closed verification |
| Download MITM | Hash check catches modified bytes |
| Binary modification | Artifact hash in chain |
| Dangerous source | Pattern scanner + CVE check |
| Noisy imports (network, subprocess, secret reads) | Import-time trace -- observed only, not blocked |
| Malicious setup.py | Static regex scan of install-time code (never executed under observation) |
| Unattested upstream release | PEP 740 provenance lookup reports presence/absence + publisher |
| Cross-package replay | Package name + version in chain hash |
| Key compromise | TOFU pinning alerts on key change |
| Key theft | Encrypted storage + OS keychain |
| Single signer risk | Multi-party N-of-M verification |
| Post-install tampering | Runtime watchdog |
| Non-reproducible build | Consensus builds |
| Dual signing | Transparency log equivocation detection |
| Pin poisoning | Deferred TOFU commit |

**Honest limitations:**

- Source audit catches known patterns, not logic bugs or novel techniques
- `sealed trace` is instrumentation, not a sandbox: it observes an import, it does not contain it, and `os.system` / `ctypes` / `_socket` / `fork` / C-extension init all bypass it (see [Import-time tracing](#import-time-tracing-not-a-sandbox))
- Tracing covers **import time only**. Install-time `setup.py` execution is never observed, only regex-scanned
- `sealed install` is a parallel install path. It does not hook, wrap or protect ordinary `pip install`
- Seals are self-signed with a TOFU-pinned local key: they attest *your* build, not the publisher's identity
- The transparency log is local SQLite with **no external witness or gossip protocol**. An attacker with write access to `~/.sealed` can rebuild the hash chain and it will still verify
- Upstream PEP 740 provenance is parsed and reported, but the Sigstore signature chain is **not** cryptographically verified; a digest match means PyPI served a statement naming that file
- Most PyPI releases have no PEP 740 provenance at all, so for those packages this adds no upstream trust
- Consensus builds on one machine verify reproducibility, not independent agreement
- `--no-deps` install and resolver fallback mean a failed resolution silently degrades to single-package mode
- Build time scales with package complexity

## Roadmap

24 modules (one of them a deprecated shim). 364 tests collected: 361 pass, 3 skip
on Windows without symlink privileges. 14 CLI commands, plus `sandbox` as a
deprecated alias of `trace`. Counts verified by `ls sealed/*.py`, `pytest` and
`sealed --help` on Python 3.12.9 -- not from memory.

Shipped:

- [x] 5-step provenance chains with Ed25519 signatures
- [x] Environment attestation (software + TPM)
- [x] Source code safety scanning
- [x] Import-time behavioral tracing (audit hook + wrappers; observability, no containment)
- [x] Upstream PyPI PEP 740 provenance lookup, recorded in the signed chain
- [x] Consensus builds (N-build majority vote)
- [x] Runtime integrity watchdog
- [x] Trust graph with weak-link analysis
- [x] Transparency log with equivocation detection
- [x] TOFU key pinning with deferred commit
- [x] Multi-party N-of-M verification
- [x] Encrypted key storage + OS keychain
- [x] Lockfile for team installs
- [x] Multi-ecosystem adapters (pip, npm, cargo)
- [x] Recursive transitive dependency sealing
- [x] SQLite registry with export/import
- [x] CI/CD GitHub Actions workflows

**Next (not built -- do not assume any of this exists):**
- Public transparency log with an external witness / gossip protocol
- Full Sigstore bundle verification (certificate chain + Rekor inclusion proof), not just parsing
- Real OS-level isolation for tracing (Windows Job Objects + restricted token; seccomp/namespaces on Linux)
- Genuine pip interception (PEP 517 backend wrapper or index shim) so ordinary `pip install` is covered
- Cross-machine consensus builds

## Documentation

- [Wiki: Quick Start](docs/wiki/Quick-Start.md)
- [Wiki: Use Cases](docs/wiki/Use-Cases.md) (10 real-world scenarios)
- [Wiki: Code Snippets](docs/wiki/Snippets.md) (12 copy-paste examples)
- [Wiki: Team Setup](docs/wiki/Team-Setup.md)
- [Wiki: CI/CD Integration](docs/wiki/CI-CD.md)
- [Wiki: CLI Reference](docs/wiki/CLI-Reference.md)
- [Wiki: Security Model](docs/wiki/Security-Model.md)
- [Wiki: Troubleshooting](docs/wiki/Troubleshooting.md)
- [Architecture](docs/ARCHITECTURE.md)
- [API Reference](docs/API.md)
- [Security](docs/SECURITY.md)

## License

Apache-2.0 | ALIA Labs

Built by [Tushar Sharma](https://github.com/TxsharDev) at ALIA Labs.
