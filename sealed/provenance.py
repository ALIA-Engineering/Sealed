"""Upstream PyPI provenance (PEP 740) lookup.

Sealed's own seals are self-signed: you sign your own build with your own key,
pinned on first use. That proves *your* machine produced *that* binary from
*that* source. It proves nothing about whether the source came from the real
publisher.

PEP 740 closes part of that gap. When a project publishes to PyPI via Trusted
Publishing, PyPI stores a Sigstore attestation bundle alongside the file and
serves it from the Integrity API::

    GET https://pypi.org/integrity/{name}/{version}/{filename}/provenance

The bundle names the publisher (GitHub repo + workflow, or GitLab project) and
carries a DSSE envelope whose in-toto Statement lists the artifact's SHA-256.
That lets Sealed answer a question its own signatures cannot: *did the upstream
publisher, identified by an OIDC identity, claim this exact file?*

Trust boundaries — what this module does and does not do
--------------------------------------------------------
* It **fetches** PyPI's published provenance and reports presence/absence.
* It **parses** the DSSE envelope and checks that the in-toto subject digest
  equals the SHA-256 of the file Sealed downloaded (``digest_match``).
* It **records** the publisher identity (repository, workflow, environment) and
  the Rekor transparency-log entry indexes.
* It does **not** verify the Sigstore signature chain. Signature verification is
  not implemented in this version: :attr:`ProvenanceInfo.signature_verified` is
  always ``None`` and reported as such, never ``True``. Without verification, a
  digest match tells you PyPI served a statement about this file — not that the
  signature is valid.
* Absence of provenance is not evidence of tampering. Most PyPI projects still
  upload with API tokens and have no attestation at all.

Sealed's local transparency log has **no external witness**: it is a SQLite
hash chain on your disk, and anyone who can write that file can rebuild it.
PyPI provenance is the only trust signal here that originates outside your
machine.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from typing import Any

import httpx

PYPI_API = "https://pypi.org/pypi"
PYPI_INTEGRITY = "https://pypi.org/integrity"

#: Documented, unavoidable caveat for the local transparency log.
LOCAL_LOG_CAVEAT = (
    "Sealed's transparency log is local SQLite with no external witness or "
    "gossip protocol. An attacker with write access to ~/.sealed can rebuild "
    "the hash chain. Upstream PyPI provenance is the only externally-anchored "
    "signal Sealed consumes."
)


class ProvenanceError(Exception):
    pass


@dataclass
class PublisherIdentity:
    """Who PyPI says published the file."""

    kind: str = ""
    repository: str = ""
    workflow: str = ""
    environment: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PublisherIdentity:
        return cls(
            kind=str(d.get("kind", "") or ""),
            repository=str(d.get("repository", "") or ""),
            workflow=str(d.get("workflow", "") or ""),
            environment=str(d.get("environment", "") or ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "repository": self.repository,
            "workflow": self.workflow,
            "environment": self.environment,
        }

    def __str__(self) -> str:
        parts = [p for p in (self.kind, self.repository, self.workflow) if p]
        return " / ".join(parts) if parts else "unknown publisher"


@dataclass
class ProvenanceInfo:
    """What PyPI published (or did not publish) about one file."""

    package: str
    version: str
    filename: str = ""
    available: bool = False
    publishers: list[PublisherIdentity] = field(default_factory=list)
    predicate_types: list[str] = field(default_factory=list)
    subject_digests: list[str] = field(default_factory=list)
    transparency_log_indexes: list[str] = field(default_factory=list)
    #: True only if the artifact SHA-256 appears as an in-toto subject digest.
    digest_match: bool | None = None
    #: Always None: Sigstore signature verification is not implemented. Sealed
    #: never silently claims cryptographic verification it did not perform.
    signature_verified: bool | None = None
    error: str | None = None

    @property
    def summary(self) -> str:
        if self.error:
            return f"provenance lookup failed: {self.error}"
        if not self.available:
            return "no PEP 740 provenance published on PyPI"
        pub = ", ".join(str(p) for p in self.publishers) or "unknown publisher"
        bits = [f"published by {pub}"]
        if self.digest_match is True:
            bits.append("attested digest matches downloaded artifact")
        elif self.digest_match is False:
            bits.append("ATTESTED DIGEST DOES NOT MATCH downloaded artifact")
        if self.signature_verified is True:
            bits.append("Sigstore signature verified")
        elif self.signature_verified is None:
            bits.append("Sigstore signature NOT verified (parsed only)")
        else:
            bits.append("Sigstore signature verification FAILED")
        return "; ".join(bits)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "filename": self.filename,
            "available": self.available,
            "publishers": [p.to_dict() for p in self.publishers],
            "predicate_types": self.predicate_types,
            "subject_digests": self.subject_digests,
            "transparency_log_indexes": self.transparency_log_indexes,
            "digest_match": self.digest_match,
            "signature_verified": self.signature_verified,
            "error": self.error,
            "summary": self.summary,
            "caveat": LOCAL_LOG_CAVEAT,
        }


def _b64_json(payload: str) -> dict[str, Any] | None:
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return json.loads(decoder(payload + "=" * (-len(payload) % 4)))
        except (binascii.Error, ValueError, TypeError):
            continue
    return None


class PyPIProvenanceClient:
    """Read-only client for PyPI's PEP 740 Integrity API."""

    def __init__(self, timeout: int = 30, base_url: str = PYPI_INTEGRITY,
                 api_url: str = PYPI_API):
        self.timeout = timeout
        self.base_url = base_url.rstrip("/")
        self.api_url = api_url.rstrip("/")

    # -- lookups ---------------------------------------------------------
    def sdist_filename(self, package: str, version: str) -> str:
        """Filename of the source distribution PyPI serves for this release."""
        url = f"{self.api_url}/{package}/{version}/json"
        resp = httpx.get(url, follow_redirects=True, timeout=self.timeout)
        if resp.status_code == 404:
            raise ProvenanceError(f"Release not found on PyPI: {package} {version}")
        resp.raise_for_status()
        for info in resp.json().get("urls", []):
            if info.get("packagetype") == "sdist":
                return info["filename"]
        raise ProvenanceError(f"No sdist for {package} {version}")

    def fetch(self, package: str, version: str, filename: str,
              artifact_sha256: str | None = None) -> ProvenanceInfo:
        """Fetch and parse provenance for one distribution file.

        A 404 means "no attestation published" — a normal, non-fatal outcome
        that is reported as ``available=False``, never raised. A 403 (denied or
        rate-limited) is reported as an error: it is not evidence of absence.
        """
        info = ProvenanceInfo(package=package, version=version, filename=filename)
        url = f"{self.base_url}/{package}/{version}/{filename}/provenance"
        try:
            resp = httpx.get(url, follow_redirects=True, timeout=self.timeout)
        except Exception as e:  # network is best-effort; absence is not failure
            info.error = f"{type(e).__name__}: {e}"
            return info

        if resp.status_code == 404:
            return info  # no provenance published (normal, non-fatal)
        if resp.status_code == 403:
            info.error = (
                "HTTP 403: PyPI denied the lookup (rate-limited or blocked); "
                "cannot tell whether attestations exist"
            )
            return info
        if resp.status_code >= 400:
            info.error = f"HTTP {resp.status_code}"
            return info

        try:
            data = resp.json()
        except ValueError as e:
            info.error = f"malformed provenance JSON: {e}"
            return info

        return self.parse(data, info, artifact_sha256)

    def for_package(self, package: str, version: str,
                    artifact_sha256: str | None = None) -> ProvenanceInfo:
        """Convenience: resolve the sdist filename, then fetch its provenance."""
        try:
            filename = self.sdist_filename(package, version)
        except Exception as e:
            return ProvenanceInfo(package=package, version=version,
                                  error=f"{type(e).__name__}: {e}")
        return self.fetch(package, version, filename, artifact_sha256)

    # -- parsing ---------------------------------------------------------
    @staticmethod
    def parse(data: dict[str, Any], info: ProvenanceInfo | None = None,
              artifact_sha256: str | None = None) -> ProvenanceInfo:
        """Parse a PEP 740 provenance object into a :class:`ProvenanceInfo`."""
        info = info or ProvenanceInfo(package="", version="")
        bundles = data.get("attestation_bundles") or []
        if not bundles:
            return info
        info.available = True

        for bundle in bundles:
            publisher = bundle.get("publisher") or {}
            if publisher:
                info.publishers.append(PublisherIdentity.from_dict(publisher))
            for att in bundle.get("attestations") or []:
                envelope = att.get("envelope") or {}
                statement = _b64_json(envelope.get("statement", "")) or {}
                ptype = statement.get("predicateType")
                if ptype and ptype not in info.predicate_types:
                    info.predicate_types.append(str(ptype))
                for subject in statement.get("subject") or []:
                    digest = (subject.get("digest") or {}).get("sha256")
                    if digest and digest not in info.subject_digests:
                        info.subject_digests.append(str(digest))
                material = att.get("verification_material") or {}
                for entry in material.get("transparency_entries") or []:
                    idx = entry.get("logIndex")
                    if idx is not None and str(idx) not in info.transparency_log_indexes:
                        info.transparency_log_indexes.append(str(idx))

        if artifact_sha256:
            info.digest_match = artifact_sha256.lower() in {
                d.lower() for d in info.subject_digests
            }
        return info


def check_provenance(package: str, version: str,
                     artifact_sha256: str | None = None,
                     client: PyPIProvenanceClient | None = None) -> ProvenanceInfo:
    """Module-level helper used by the CLI and the build pipeline."""
    return (client or PyPIProvenanceClient()).for_package(
        package, version, artifact_sha256
    )
