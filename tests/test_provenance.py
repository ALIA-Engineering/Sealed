"""Tests for upstream PyPI (PEP 740) provenance consumption."""

import base64
import json

import pytest

from sealed.provenance import (
    LOCAL_LOG_CAVEAT,
    ProvenanceError,
    ProvenanceInfo,
    PublisherIdentity,
    PyPIProvenanceClient,
    check_provenance,
)

ARTIFACT_SHA = "20ffe791c1fa33ce62148c0291b46280d29c1910964d9afac419e9b1a8afc56b"


def _statement(digest: str = ARTIFACT_SHA) -> str:
    stmt = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://docs.pypi.org/attestations/publish/v1",
        "subject": [{"name": "pkg-1.0.tar.gz", "digest": {"sha256": digest}}],
    }
    return base64.b64encode(json.dumps(stmt).encode()).decode()


def _bundle(digest: str = ARTIFACT_SHA) -> dict:
    return {
        "attestation_bundles": [{
            "publisher": {
                "kind": "GitHub",
                "repository": "example/pkg",
                "workflow": "release.yml",
                "environment": "pypi",
            },
            "attestations": [{
                "version": 1,
                "verification_material": {
                    "certificate": "MIIC...",
                    "transparency_entries": [{"logIndex": "2084808872"}],
                },
                "envelope": {"statement": _statement(digest), "signature": "MEUC..."},
            }],
        }]
    }


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class TestParse:
    def test_parses_publisher_and_predicate(self):
        info = PyPIProvenanceClient.parse(_bundle())
        assert info.available
        assert info.publishers[0].repository == "example/pkg"
        assert info.predicate_types == ["https://docs.pypi.org/attestations/publish/v1"]
        assert info.transparency_log_indexes == ["2084808872"]

    def test_digest_match_true(self):
        info = PyPIProvenanceClient.parse(_bundle(), artifact_sha256=ARTIFACT_SHA)
        assert info.digest_match is True

    def test_digest_match_false_on_mismatch(self):
        info = PyPIProvenanceClient.parse(_bundle(), artifact_sha256="deadbeef")
        assert info.digest_match is False

    def test_digest_match_none_when_not_supplied(self):
        assert PyPIProvenanceClient.parse(_bundle()).digest_match is None

    def test_empty_bundles_means_unavailable(self):
        info = PyPIProvenanceClient.parse({"attestation_bundles": []})
        assert info.available is False

    def test_signature_never_claimed_verified(self):
        info = PyPIProvenanceClient.parse(_bundle())
        assert info.signature_verified is None
        assert "NOT verified" in info.summary

    def test_malformed_statement_does_not_crash(self):
        data = _bundle()
        data["attestation_bundles"][0]["attestations"][0]["envelope"]["statement"] = "!!!"
        info = PyPIProvenanceClient.parse(data)
        assert info.available is True
        assert info.subject_digests == []


class TestFetch:
    def test_404_is_absence_not_error(self, monkeypatch):
        monkeypatch.setattr("httpx.get", lambda *a, **k: FakeResponse(404))
        info = PyPIProvenanceClient().fetch("six", "1.17.0", "six-1.17.0.tar.gz")
        assert info.available is False
        assert info.error is None
        assert "no PEP 740 provenance" in info.summary

    def test_403_is_error_not_absence(self, monkeypatch):
        monkeypatch.setattr("httpx.get", lambda *a, **k: FakeResponse(403))
        info = PyPIProvenanceClient().fetch("pkg", "1.0", "pkg-1.0.tar.gz")
        assert info.available is False
        assert info.error is not None
        assert "403" in info.error
        assert "no PEP 740 provenance" not in info.summary

    def test_200_parses_bundle(self, monkeypatch):
        monkeypatch.setattr("httpx.get", lambda *a, **k: FakeResponse(200, _bundle()))
        info = PyPIProvenanceClient().fetch("pkg", "1.0", "pkg-1.0.tar.gz",
                                            artifact_sha256=ARTIFACT_SHA)
        assert info.available and info.digest_match is True
        assert "example/pkg" in info.summary

    def test_server_error_is_reported(self, monkeypatch):
        monkeypatch.setattr("httpx.get", lambda *a, **k: FakeResponse(500))
        info = PyPIProvenanceClient().fetch("pkg", "1.0", "pkg-1.0.tar.gz")
        assert info.error == "HTTP 500"

    def test_network_exception_is_not_fatal(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("dns fail")
        monkeypatch.setattr("httpx.get", boom)
        info = PyPIProvenanceClient().fetch("pkg", "1.0", "pkg-1.0.tar.gz")
        assert info.available is False
        assert "dns fail" in info.error

    def test_for_package_resolves_sdist_then_fetches(self, monkeypatch):
        calls = []

        def fake_get(url, **k):
            calls.append(url)
            if url.endswith("/json"):
                return FakeResponse(200, {"urls": [
                    {"packagetype": "bdist_wheel", "filename": "pkg-1.0-py3-none-any.whl"},
                    {"packagetype": "sdist", "filename": "pkg-1.0.tar.gz"},
                ]})
            return FakeResponse(200, _bundle())

        monkeypatch.setattr("httpx.get", fake_get)
        info = PyPIProvenanceClient().for_package("pkg", "1.0")
        assert info.filename == "pkg-1.0.tar.gz"
        assert calls[1].endswith("/integrity/pkg/1.0/pkg-1.0.tar.gz/provenance")

    def test_for_package_reports_missing_sdist(self, monkeypatch):
        monkeypatch.setattr("httpx.get", lambda *a, **k: FakeResponse(200, {"urls": []}))
        info = PyPIProvenanceClient().for_package("pkg", "1.0")
        assert "No sdist" in info.error

    def test_sdist_filename_404(self, monkeypatch):
        monkeypatch.setattr("httpx.get", lambda *a, **k: FakeResponse(404))
        with pytest.raises(ProvenanceError):
            PyPIProvenanceClient().sdist_filename("nope", "1.0")


class TestReporting:
    def test_to_dict_documents_local_log_caveat(self):
        d = ProvenanceInfo(package="p", version="1").to_dict()
        assert d["caveat"] == LOCAL_LOG_CAVEAT
        assert "no external witness" in LOCAL_LOG_CAVEAT

    def test_publisher_str(self):
        p = PublisherIdentity(kind="GitHub", repository="a/b", workflow="r.yml")
        assert str(p) == "GitHub / a/b / r.yml"
        assert str(PublisherIdentity()) == "unknown publisher"

    def test_check_provenance_helper_uses_client(self, monkeypatch):
        monkeypatch.setattr("httpx.get", lambda *a, **k: FakeResponse(200, _bundle()))
        client = PyPIProvenanceClient()
        monkeypatch.setattr(client, "sdist_filename", lambda p, v: "pkg-1.0.tar.gz")
        info = check_provenance("pkg", "1.0", ARTIFACT_SHA, client=client)
        assert info.digest_match is True


class TestChainIntegration:
    def test_records_provenance_step_in_chain(self, monkeypatch):
        from sealed.chain import ProvenanceChain
        from sealed.cli import _record_upstream_provenance

        monkeypatch.setattr("httpx.get", lambda *a, **k: FakeResponse(200, _bundle()))
        monkeypatch.setattr(PyPIProvenanceClient, "sdist_filename",
                            lambda self, p, v: "pkg-1.0.tar.gz")
        chain = ProvenanceChain(package_name="pkg", package_version="1.0")
        info = _record_upstream_provenance(chain, "pkg", "1.0", ARTIFACT_SHA)
        assert info.available
        rec = chain.records[-1]
        assert rec.step == "upstream_provenance"
        assert rec.metadata["available"] is True
        assert rec.metadata["digest_match"] is True
        assert rec.metadata["signature_verified"] is None

    def test_absent_provenance_still_recorded(self, monkeypatch):
        from sealed.chain import ProvenanceChain
        from sealed.cli import _record_upstream_provenance

        monkeypatch.setattr("httpx.get", lambda *a, **k: FakeResponse(404))
        monkeypatch.setattr(PyPIProvenanceClient, "sdist_filename",
                            lambda self, p, v: "pkg-1.0.tar.gz")
        chain = ProvenanceChain(package_name="pkg", package_version="1.0")
        _record_upstream_provenance(chain, "pkg", "1.0", ARTIFACT_SHA)
        assert chain.records[-1].metadata["available"] is False


@pytest.mark.network
class TestLivePyPI:
    def test_sigstore_has_provenance(self):
        info = PyPIProvenanceClient().for_package("sigstore", "4.4.0")
        assert info.available
        assert info.publishers[0].repository == "sigstore/sigstore-python"

    def test_six_has_no_provenance(self):
        info = PyPIProvenanceClient().for_package("six", "1.17.0")
        assert info.available is False
