"""Tests for import-time behavioral tracing (sealed.tracer)."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from sealed.tracer import (
    KNOWN_BYPASSES,
    NOT_A_SANDBOX_WARNING,
    ImportTracer,
    TracedBehavior,
    TraceResult,
    _MONITOR_SCRIPT,
)


class TestTraceResult:
    def test_clean_when_no_behaviors(self):
        r = TraceResult(package="test", version="1.0")
        assert r.clean

    def test_clean_with_info_only(self):
        r = TraceResult(package="test", version="1.0", behaviors=[
            TracedBehavior(type="import_success", severity="info"),
        ])
        assert r.clean

    def test_not_clean_with_critical(self):
        r = TraceResult(package="test", version="1.0", behaviors=[
            TracedBehavior(type="network_connect", severity="critical",
                           details={"address": "evil.com:443"}),
        ])
        assert not r.clean

    def test_not_clean_with_high(self):
        r = TraceResult(package="test", version="1.0", behaviors=[
            TracedBehavior(type="subprocess", severity="high"),
        ])
        assert not r.clean

    def test_safe_is_alias_for_clean(self):
        r = TraceResult(package="t", version="1.0", behaviors=[
            TracedBehavior(type="subprocess", severity="high"),
        ])
        assert r.safe is r.clean is False

    def test_never_claims_containment(self):
        r = TraceResult(package="t", version="1.0")
        assert r.contained is False
        d = r.to_dict()
        assert d["contained"] is False
        assert "not containment" in d["warning"]

    def test_to_dict_keeps_backcompat_keys(self):
        r = TraceResult(package="pkg", version="2.0", behaviors=[
            TracedBehavior(type="import_success", severity="info"),
        ])
        d = r.to_dict()
        assert d["package"] == "pkg"
        assert d["safe"] is True and d["clean"] is True
        assert d["critical"] == 0

    def test_digest_deterministic(self):
        mk = lambda: TraceResult(package="a", version="1.0", behaviors=[
            TracedBehavior(type="x", severity="info"),
        ])
        assert mk().digest == mk().digest

    def test_import_error_result_is_not_clean(self):
        r = TraceResult(package="p", version="1.0", behaviors=[
            TracedBehavior(type="import_error", severity="critical",
                           details={"package": "p", "error": "boom"}),
        ])
        assert not r.clean
        assert r.to_dict()["critical"] == 1


class TestTracedBehavior:
    def test_to_dict(self):
        b = TracedBehavior(type="network_connect", severity="critical",
                           details={"address": "evil.com:443"})
        d = b.to_dict()
        assert d["type"] == "network_connect"
        assert d["address"] == "evil.com:443"


class TestImportTracer:
    def test_trace_stdlib_module(self):
        result = ImportTracer(timeout=30).trace("json", "stdlib")
        assert result.error is None or result.behaviors
        assert result.contained is False

    def test_restricted_env(self):
        env = ImportTracer()._restricted_env()
        assert env["SEALED_TRACE"] == "1"
        assert env["SEALED_SANDBOX"] == "1"  # back-compat marker
        assert "AWS_SECRET_ACCESS_KEY" not in env
        assert "GITHUB_TOKEN" not in env

    def test_warning_is_advertised(self):
        assert "not containment" in NOT_A_SANDBOX_WARNING
        assert ImportTracer.warning == NOT_A_SANDBOX_WARNING
        assert ImportTracer.bypasses == KNOWN_BYPASSES

    def test_documented_bypasses_are_specific(self):
        joined = " ".join(KNOWN_BYPASSES)
        for token in ("os.system", "ctypes", "_socket"):
            assert token in joined

    def test_analyze_is_deprecated_alias(self):
        tracer = ImportTracer(timeout=30)
        with pytest.deprecated_call():
            result = tracer.analyze("json", "stdlib")
        assert isinstance(result, TraceResult)


def _run_monitor(payload_module_src: str) -> list[dict]:
    """Write a throwaway module, trace importing it, return recorded behaviors."""
    tmp = Path(tempfile.mkdtemp(prefix="sealed_tracer_test_"))
    (tmp / "victim_mod.py").write_text(payload_module_src)
    script = tmp / "monitor.py"
    script.write_text(_MONITOR_SCRIPT)
    out = tmp / "out.json"
    env = ImportTracer()._restricted_env()
    env["PYTHONPATH"] = str(tmp)
    subprocess.run([sys.executable, str(script), "victim_mod", str(out)],
                   capture_output=True, timeout=60, env=env)
    return json.loads(out.read_text())["behaviors"]


class TestMonitorCoverage:
    """The tracer must actually observe the behaviors it claims to observe."""

    def test_records_env_secret_access(self):
        behaviors = _run_monitor("import os\nos.getenv('MY_API_KEY')\n")
        assert any(b["type"] == "env_secret_access" for b in behaviors)

    def test_records_subprocess_attempt(self):
        behaviors = _run_monitor(
            "import subprocess\ntry:\n subprocess.Popen(['whoami'])\nexcept Exception:\n pass\n"
        )
        assert any(b["type"] == "subprocess" for b in behaviors)

    def test_audit_hook_catches_os_system_bypass(self):
        """os.system bypasses the Popen wrapper; the audit hook still sees it."""
        behaviors = _run_monitor(
            "import os\ntry:\n os.system('cd .')\nexcept Exception:\n pass\n"
        )
        recorded = [b for b in behaviors if b["type"] == "os_system"]
        assert recorded, behaviors
        # Recorded, but NOT prevented: this is instrumentation, not containment.
        assert recorded[0]["source"] == "audit"

    def test_audit_hook_catches_ctypes_native_load(self):
        behaviors = _run_monitor(
            "import ctypes\ntry:\n"
            " ctypes.CDLL('kernel32' if __import__('sys').platform=='win32' else 'libc.so.6')\n"
            "except Exception:\n pass\n"
        )
        assert any(b["type"] == "native_code_load" for b in behaviors), behaviors

    def test_import_error_is_recorded_not_raised(self):
        behaviors = _run_monitor("raise RuntimeError('boom')\n")
        errs = [b for b in behaviors if b["type"] == "import_error"]
        assert errs
        # A failed import means nothing was traced: it must never look "clean".
        assert errs[0]["severity"] == "critical"


class TestDeprecatedSandboxShim:
    def test_old_names_still_import(self):
        from sealed.sandbox import (
            BehavioralSandbox, SandboxBehavior, SandboxResult,
        )
        assert BehavioralSandbox is ImportTracer
        assert SandboxResult is TraceResult
        assert SandboxBehavior is TracedBehavior

    def test_shim_docstring_disclaims_containment(self):
        import sealed.sandbox as shim
        assert "no containment" in shim.__doc__

    def test_package_exports_new_names(self):
        import sealed
        assert sealed.ImportTracer is ImportTracer
        assert sealed.BehavioralSandbox is ImportTracer
