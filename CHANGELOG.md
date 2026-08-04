# Changelog

## v0.1.1 (2026-08-04)

**Renamed: "behavioral sandbox" -> import-time behavioral tracing**
- `sealed/sandbox.py` is now a deprecated shim over the new `sealed/tracer.py`.
  `ImportTracer` / `TraceResult` / `TracedBehavior` replace `BehavioralSandbox` /
  `SandboxResult` / `SandboxBehavior` (old names still import).
- CLI: `sealed trace` replaces `sealed sandbox` (kept as a deprecated alias).
- The feature never provided containment. Docs, CLI help and docstrings now say so
  explicitly and list the specific bypasses (`os.system`, `ctypes`, `_socket`,
  fork/exec, C extension init, raw syscalls), plus the import-time-only scope.
- Tracing coverage improved with a CPython audit hook (`sys.addaudithook`), which
  records `os.system`, `os.exec*`/`os.spawn*`, `ctypes.dlopen`, `socket.connect`
  and sensitive `open` calls that the old monkey-patches missed. Recorded, not blocked.
- `TraceResult.contained` is always `False` and is serialized, so downstream
  consumers cannot assume containment.

**Added: upstream PyPI provenance (PEP 740)**
- New `sealed/provenance.py`: reads PyPI's Integrity API and reports whether a
  release has a publisher attestation bundle, the publisher identity, in-toto
  predicate type, subject digests and Rekor log indexes.
- New `sealed provenance <package>` command (`--version`, `--sha256`, `--json`).
- `sealed install` / `sealed build` record an `upstream_provenance` step in the
  signed chain, so presence/absence is part of what gets signed.
- The Sigstore signature chain is parsed, not verified: `signature_verified` is
  reported as `null`, never `true`.

**Documentation honesty**
- README, wiki, `docs/API.md`, `docs/SECURITY.md`, `docs/ARCHITECTURE.md` now state
  that `sealed install` is an alternative install path, not a guard on pip.
- Documented that the transparency log is local SQLite with no external witness.
- Counts corrected: 24 modules, 364 tests, 14 CLI commands (+1 deprecated alias).

**Security fixes**
- `sealed/tracer.py`: the trace output file is now created with
  `tempfile.NamedTemporaryFile` instead of `tempfile.mktemp`. The old code used
  a predictable path that a local attacker could pre-seat with a symlink,
  turning the tracer's final `json.dump` into an arbitrary-file truncate.
- `sealed/tracer.py` / `sealed/cli.py`: a package that fails to import now
  records `import_error` at `critical` severity and `sealed trace` exits
  non-zero with an explicit "IMPORT FAILED" message. Previously the failure
  was logged as `info`, the trace reported "NO FINDINGS" and exited 0 -- a
  false clean bill for a package the tracer never actually observed.
- `sealed/cli.py`: store paths (`~/.sealed/store/<package>-<version>`) now
  reject `/`, `\`, `..` and empty components instead of joining them raw.
- `sealed/provenance.py`: removed the dead `verify_bundle` reference from the
  docstring; signature verification is not implemented, and the docs now say
  so. `signature_verified` remains `None` (never `true`).
- `sealed/provenance.py`: HTTP 403 from the PyPI Integrity API is now reported
  as an error ("rate-limited or blocked"), not conflated with 404 ("no
  attestation published").

**Housekeeping**
- Registered the `network` pytest marker in `pyproject.toml` (silences
  `PytestUnknownMarkWarning`).
- `paper/*.aux` and `paper/*.out` added to `.gitignore`; generated LaTeX
  artifacts removed from the working tree.
- LICENSE: replaced the stub with the full Apache-2.0 text.
- README badge no longer hardcodes a test count.

## v0.1.0 (2026-06-11)

Initial release. Full-stack supply chain attestation in one command.

**Core Pipeline:**
- `sealed install <package>`: resolve deps, build each from source, audit, attest, seal, verify, policy check, install
- `sealed build <package>`: build and seal without installing
- `sealed verify`: verify a sealed artifact (signature + chain + artifact hash + chain links)
- `sealed inspect`: print seal or chain contents
- `sealed audit`: list all sealed packages with attestation method
- `sealed reproduce <package>`: build twice and compare for reproducibility

**5-Step Provenance Chain:**
- Environment attestation: Python, pip, OS, CPU, compiler, env vars, TPM PCRs
- Source audit: pattern scan (dangerous calls), setup.py analysis, CVE check (pip-audit)
- Source verification: SHA-256 fail-closed against PyPI registry
- Toolchain capture: Python interpreter hash
- Build: source dir hash to artifact hash

**Environment Attestation:**
- Software attestation: 7 measured components hashed into chain
- TPM 2.0 attestation: PCR values + hardware quote (when tpm2-tools available)

**Source Code Safety:**
- Pattern scanner: detects dangerous calls in source before building
- Setup.py analyzer: detects install-time code execution
- CVE check: pip-audit integration (when installed)
- Audit results recorded in provenance chain as `source_audit` step

**Encrypted Key Storage:**
- PBKDF2 key derivation (100K iterations) + NaCl SecretBox encryption
- Passphrase-protected keys via `sealed keygen --passphrase`
- Auto-prompts on first use (interactive terminals)
- chmod 600 on Unix, backwards compatible with plaintext keys

**Reproducibility Verification:**
- `sealed reproduce <package>`: builds twice from same source, compares
- Wheel diff: file-by-file content comparison
- Normalized comparison: strips RECORD/timestamps, checks content identity
- Reports exact differences when builds diverge

**Recursive Dependency Sealing:**
- Topological dependency resolution via `pip install --dry-run --report`
- All transitive dependencies sealed, not just top-level
- Skip already-sealed packages in local store
- `--no-deps` flag for single-package mode

**Shared Registry:**
- SQLite-backed seal and chain storage
- Export/import seals with signature verification on import
- Export/import key pins
- Query by package, version, or signing key

**Trust-on-First-Use (TOFU) Key Pinning:**
- Auto-pin signing key on first encounter
- Key pinning deferred until ALL policy checks pass (prevents pin poisoning)
- Key mismatch detection and rejection
- Manual key pinning and revocation with reason tracking

**Multi-Party Verification:**
- Configurable `min_signatures` policy
- Multiple independent signers stored per package-version
- N-of-M verification

**Trust Policy Engine:**
- `sealed policy show/set/reset` CLI
- Configurable: min signatures, TOFU toggle, pin enforcement, attestation requirements
- Policy evaluated on every install

**Security Hardening:**
- Python 3.10+ compatible tarfile extraction (manual path check on <3.12, filter="data" on 3.12+)
- Zip path traversal protection
- Symlink skipping in directory hashing
- Specific exception handling in crypto verification
- Private key rejection in trusted-key CLI
- Seal.from_dict filters unknown keys (prevents crash on extra fields)
- Registry close on all exit paths (no resource leaks)

**Testing:**
- 213 tests, 3 skipped (Windows symlinks)
- Coverage: chain, seal, verify, attestation, source audit, keystore, reproducibility, registry, key pinning, revocation, multi-party, policy, dependency resolution, edge cases, integration
