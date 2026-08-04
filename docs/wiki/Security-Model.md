# Security Model

## What Sealed Proves

| Claim | How |
|-------|-----|
| Binary came from this source | SHA-256 chain from source dir to artifact |
| Source matches PyPI's registry | SHA-256 fail-closed against PyPI digest |
| Source was scanned for dangers | Pattern scan + CVE check + setup.py analysis |
| Build environment is known | 7-component software attestation, TPM when available |
| Nobody modified the chain | Ed25519 signature over chain hash |
| Your signing key is consistent | TOFU pinning, deferred commit |
| Enough people verified | Multi-party N-of-M |
| Post-install files are intact | Runtime watchdog hash check |
| Build is reproducible | Consensus builds (N-build comparison) |
| No dual-signing happened | Transparency log equivocation detection |

## What Sealed Does NOT Prove

| Gap | Why | Mitigation |
|-----|-----|------------|
| Source code is safe | Sealed scans patterns, not logic | Use code review tools |
| Untrusted code can be run safely | `sealed trace` is instrumentation, **not** a sandbox: no containment of any kind | Use a disposable VM/container. Never run untrusted code under `sealed trace` |
| Install-time code is observed | Only *import* time is traced; `setup.py` is regex-scanned, never observed executing | Read the source, or install into a throwaway environment |
| `pip install` is protected | `sealed install` is a parallel path; pip is untouched | Use `sealed install` explicitly |
| The transparency log is tamper-proof | Local SQLite, no external witness -- local write access lets an attacker rebuild the chain | Export seals off-machine; consult upstream PEP 740 provenance |
| A seal proves the publisher's identity | Seals are self-signed with your TOFU-pinned key | `sealed provenance` reports upstream PyPI attestations where they exist |
| Consensus = independent agreement | Same machine, same toolchain | True consensus needs multiple machines |
| Transparency log is public | Local-only, no gossip protocol | Detects local equivocation only |
| Build machine is clean (no TPM) | Software attestation measures, doesn't prove | Use TPM when available |

## Threat Model

### Attacks Sealed Catches

**Mirror tampering.** You download from a compromised PyPI mirror. Sealed verifies the SHA-256 hash against PyPI's API response. Hash mismatch = download rejected.

**Man-in-the-middle.** Someone intercepts your download and swaps the binary. The hash won't match. Rejected.

**Post-build modification.** Malware modifies the installed wheel after building. The artifact hash in the chain doesn't match. Rejected.

**Typosquatting.** You install `reqeusts` instead of `requests`. The source audit catches dangerous patterns (network calls, file access, subprocess spawning) before the build even starts.

**Key compromise detection.** An attacker gets your teammate's signing key. They seal a malicious build. But your TOFU pin says this package was previously signed by a different key. Mismatch detected, install blocked.

**Pin poisoning.** An attacker submits a malicious seal that fails signature verification but tries to pin their key. Sealed defers the pin commit until ALL policy checks pass. The pin is never written.

### Attacks Sealed Does NOT Catch

**Compromised build machine (no TPM).** If the machine running `sealed install` is already owned, the attacker controls the key, the build, and the chain. TPM attestation mitigates this by binding measurements to hardware.

**Source-level backdoor.** If the source code itself contains a backdoor (like xz utils), Sealed will faithfully build and seal it. The source audit catches common patterns but not targeted attacks.

**Anything that wants to evade `sealed trace`.** The tracer is instrumentation, not
containment. Traced imports run with your full privileges. Documented bypasses:
`os.system`/`os.popen` (recorded by the audit hook, still executed), `ctypes`/`cffi`
native calls, `_socket` (the C accelerator under `socket`), `os.fork`/`os.spawn*`/
`os.exec*` (the child has no hooks), C extension module init, and raw syscalls that
emit no audit event. **Do not rely on it to run untrusted code.**

**Install-time execution.** `setup.py` runs during install, not import. `sealed trace`
never sees it; `audit_source.py` only regex-scans it.

**Local transparency-log rewriting.** The log is SQLite under `~/.sealed` with no
external witness or gossip protocol. An attacker with local write access can rebuild
the whole hash chain and it will verify.

**Anything installed by plain `pip`.** Sealed does not intercept pip.
