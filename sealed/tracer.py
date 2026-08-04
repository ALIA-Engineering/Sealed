"""Import-time behavioral tracing (instrumentation, NOT containment).

WHAT THIS IS
------------
`ImportTracer` runs ``import <package>`` inside a *separate, ordinary* Python
interpreter with observability hooks installed:

* a CPython audit hook (:func:`sys.addaudithook`) that records ``socket.connect``,
  ``subprocess.Popen``, ``os.system``, ``os.exec``, ``os.spawn``, ``ctypes.dlopen``,
  ``exec``/``compile`` and sensitive ``open`` calls, and
* Python-level wrappers around ``socket.socket``, ``subprocess.Popen``,
  ``builtins.open`` and ``os.getenv``.

The result is a *trace*: a list of interesting things the package did while it
was being imported. That is useful triage signal. It is not a security boundary.

WHAT THIS IS NOT — READ THIS BEFORE YOU RUN UNTRUSTED CODE
----------------------------------------------------------
**This is observability, not containment. Do not rely on it to run untrusted
code.** The traced code runs with your user's full privileges: your filesystem,
your network, your credentials. Nothing is dropped, jailed, or namespaced.

Known, trivial bypasses (non-exhaustive):

* ``os.system("curl ...")`` / ``os.popen`` — no ``subprocess.Popen`` wrapper is
  involved. The audit hook *records* it, but it still executes.
* ``ctypes`` — ``ctypes.CDLL("libc.so.6").system(...)`` or
  ``ctypes.windll.kernel32`` calls native code directly. Recorded at
  ``dlopen`` time at best; individual calls are invisible.
* ``_socket`` — the C accelerator module underneath ``socket``. Rebinding
  ``socket.socket`` in Python does not touch it.
* ``os.fork``/``os.spawnv``/``os.execv`` — a child process starts with a clean
  interpreter and none of these hooks.
* C extension modules — their module-init code runs before any Python hook can
  see it, and raw syscalls never surface as audit events.
* ``sys.addaudithook`` cannot be removed, but native code can simply not go
  through CPython at all.

Also note the scope limit: this only observes **import time**. The dominant
supply-chain risk — ``setup.py`` executing during *install* — is not covered
here at all; that is statically scanned by :mod:`sealed.audit_source`.

If you need real isolation, run the package in a disposable VM or container
with no network and no credentials. Sealed does not provide one.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sealed.chain import _hash_bytes

#: One-line banner printed by the CLI and embedded in machine-readable output.
NOT_A_SANDBOX_WARNING = (
    "This is observability, not containment. Traced code runs with your full "
    "privileges and can bypass every hook (os.system, ctypes, _socket, fork/exec, "
    "C extension init). Do not use it to run untrusted code."
)

#: The specific bypasses documented above, in machine-readable form.
KNOWN_BYPASSES = (
    "os.system / os.popen (recorded, not blocked)",
    "ctypes / cffi native calls (CDLL, windll)",
    "_socket (C accelerator under socket)",
    "os.fork / os.spawn* / os.exec* (child has no hooks)",
    "C extension module init (runs below the Python layer)",
    "raw syscalls that emit no audit event",
)

_MAX_EVENTS = 500

_MONITOR_SCRIPT = r"""import sys, json, os, importlib
_behaviors = []
_MAX = 500
_seen = set()
def _rec(ev):
    if len(_behaviors) >= _MAX:
        return
    k = json.dumps(ev, sort_keys=True)
    if k in _seen:
        return
    _seen.add(k)
    _behaviors.append(ev)

_SENSITIVE_PATHS = ['.ssh','.gnupg','.aws','.env','.netrc','.docker','.kube',
                    'id_rsa','id_ed25519','credentials']
_SECRET_ENV = ['token','secret','password','api_key','apikey','private_key','access_key']

def _sensitive(p):
    ps = str(p).lower().replace(chr(92), '/')
    for s in _SENSITIVE_PATHS:
        if s in ps:
            return s
    return None

# --- CPython audit hook: sees os.system, ctypes, exec, fork, raw socket use ---
def _audit(event, args):
    try:
        if event == 'socket.connect':
            _rec({'type': 'network_connect', 'address': str(args[2])[:200],
                  'source': 'audit', 'severity': 'critical'})
        elif event in ('socket.bind', 'socket.getaddrinfo'):
            _rec({'type': 'network_' + event.split('.')[1], 'detail': str(args[1:])[:200],
                  'source': 'audit', 'severity': 'high' if event == 'socket.bind' else 'low'})
        elif event == 'subprocess.Popen':
            _rec({'type': 'subprocess', 'command': str(args[0])[:300],
                  'source': 'audit', 'severity': 'high'})
        elif event == 'os.system':
            _rec({'type': 'os_system', 'command': str(args[0])[:300],
                  'source': 'audit', 'severity': 'critical'})
        elif event in ('os.exec', 'os.spawn', 'os.posix_spawn'):
            _rec({'type': 'process_spawn', 'event': event, 'detail': str(args)[:300],
                  'source': 'audit', 'severity': 'critical'})
        elif event == 'os.fork':
            _rec({'type': 'fork', 'source': 'audit', 'severity': 'high'})
        elif event in ('ctypes.dlopen', 'ctypes.dlsym', 'ctypes.dlsym/handle'):
            _rec({'type': 'native_code_load', 'event': event, 'detail': str(args)[:300],
                  'source': 'audit', 'severity': 'high'})
        elif event == 'exec':
            _rec({'type': 'dynamic_exec', 'source': 'audit', 'severity': 'low'})
        elif event == 'open':
            hit = _sensitive(args[0])
            if hit:
                _rec({'type': 'sensitive_file_read', 'path': str(args[0])[:300],
                      'pattern': hit, 'source': 'audit', 'severity': 'critical'})
        elif event in ('urllib.Request', 'http.client.connect'):
            _rec({'type': 'http_request', 'detail': str(args[:2])[:300],
                  'source': 'audit', 'severity': 'critical'})
    except Exception:
        pass

try:
    sys.addaudithook(_audit)
except Exception:
    pass

# --- Python-level wrappers (also *block* the easy paths, best effort) ---
try:
    import socket as _sm
    _orig_socket = _sm.socket
    class _TracedSocket(_orig_socket):
        def connect(s, addr):
            _rec({'type': 'network_connect', 'address': str(addr)[:200],
                  'source': 'wrapper', 'severity': 'critical'})
            raise ConnectionRefusedError('blocked by sealed tracer')
        def connect_ex(s, addr):
            _rec({'type': 'network_connect', 'address': str(addr)[:200],
                  'source': 'wrapper', 'severity': 'critical'})
            return 111
    _sm.socket = _TracedSocket
except Exception:
    pass

try:
    import subprocess as _sub
    class _TracedPopen:
        def __init__(s, *a, **k):
            _rec({'type': 'subprocess',
                  'command': str(a[0] if a else k.get('args', '?'))[:300],
                  'source': 'wrapper', 'severity': 'high'})
            raise PermissionError('blocked by sealed tracer')
    _sub.Popen = _TracedPopen
except Exception:
    pass

_real_open = open
def _traced_open(f, *a, **k):
    hit = _sensitive(f)
    if hit:
        _rec({'type': 'sensitive_file_read', 'path': str(f)[:300], 'pattern': hit,
              'source': 'wrapper', 'severity': 'critical'})
    return _real_open(f, *a, **k)
import builtins
builtins.open = _traced_open

_real_getenv = os.getenv
def _traced_getenv(k, d=None):
    for p in _SECRET_ENV:
        if p in k.lower():
            _rec({'type': 'env_secret_access', 'variable': k,
                  'source': 'wrapper', 'severity': 'high'})
    return _real_getenv(k, d)
os.getenv = _traced_getenv

pkg_name, out_file = sys.argv[1], sys.argv[2]
try:
    importlib.import_module(pkg_name)
    _rec({'type': 'import_success', 'package': pkg_name, 'severity': 'info'})
except Exception as e:
    _rec({'type': 'import_error', 'package': pkg_name, 'error': str(e)[:500],
          'severity': 'critical'})
with _real_open(out_file, 'w') as fh:
    json.dump({'behaviors': _behaviors}, fh)
"""


@dataclass
class TracedBehavior:
    """One observed event. Observed — not prevented."""

    type: str
    severity: str
    details: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "severity": self.severity, **self.details}


@dataclass
class TraceResult:
    """Result of an import-time trace.

    ``clean`` means *nothing interesting was observed*. It does **not** mean the
    package is safe: see :data:`NOT_A_SANDBOX_WARNING`.
    """

    package: str
    version: str
    behaviors: list[TracedBehavior] = field(default_factory=list)
    timeout: bool = False
    error: str | None = None

    #: Always False. Sealed provides no containment; kept explicit so callers
    #: and serialized output cannot quietly assume otherwise.
    contained: bool = field(default=False, init=False)

    @property
    def clean(self) -> bool:
        """True if no high/critical events were observed. Not a safety verdict."""
        return not any(b.severity in ("critical", "high") for b in self.behaviors)

    @property
    def safe(self) -> bool:
        """Deprecated alias for :attr:`clean`. The name overstates the result."""
        return self.clean

    @property
    def digest(self) -> str:
        data = json.dumps(
            [b.to_dict() for b in self.behaviors], sort_keys=True, separators=(",", ":")
        )
        return _hash_bytes(data.encode())

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "clean": self.clean,
            "safe": self.clean,  # back-compat key
            "contained": False,
            "warning": NOT_A_SANDBOX_WARNING,
            "timeout": self.timeout,
            "error": self.error,
            "behaviors": [b.to_dict() for b in self.behaviors],
            "critical": sum(1 for b in self.behaviors if b.severity == "critical"),
            "high": sum(1 for b in self.behaviors if b.severity == "high"),
        }


class ImportTracer:
    """Import a package in a child interpreter and record what it does.

    Instrumentation only. See the module docstring for the bypass list; this
    class makes no attempt to contain the code it runs.
    """

    #: Mirrors :data:`NOT_A_SANDBOX_WARNING` for callers that only hold a tracer.
    warning = NOT_A_SANDBOX_WARNING
    bypasses = KNOWN_BYPASSES

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    def trace(
        self, package: str, version: str, wheel_path: Path | None = None
    ) -> TraceResult:
        result = TraceResult(package=package, version=version)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as sf:
            sf.write(_MONITOR_SCRIPT)
            script_path = sf.name
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                         delete=False) as ofh:
            output_path = ofh.name
        try:
            import_name = package.replace("-", "_").replace(".", "_")
            env = self._restricted_env()
            if wheel_path:
                install_dir = tempfile.mkdtemp(prefix="sealed_trace_")
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", str(wheel_path),
                     "--target", install_dir, "--quiet", "--no-deps"],
                    capture_output=True, timeout=60, env=env,
                )
                env["PYTHONPATH"] = install_dir
            proc = subprocess.run(
                [sys.executable, script_path, import_name, output_path],
                capture_output=True, text=True, timeout=self.timeout, env=env,
            )
            if Path(output_path).exists():
                data = json.loads(Path(output_path).read_text())
                for b in data.get("behaviors", [])[:_MAX_EVENTS]:
                    bt = b.pop("type", "unknown")
                    sv = b.pop("severity", "info")
                    result.behaviors.append(
                        TracedBehavior(type=bt, severity=sv, details=b)
                    )
                for b in result.behaviors:
                    if b.type == "import_error":
                        result.error = b.details.get("error") or "Import failed"
                        break
            if proc.returncode != 0 and not result.behaviors:
                result.error = proc.stderr[:500] if proc.stderr else "Unknown error"
        except subprocess.TimeoutExpired:
            result.timeout = True
            result.behaviors.append(
                TracedBehavior(type="timeout", severity="high",
                               details={"seconds": str(self.timeout)})
            )
        except Exception as e:
            result.error = str(e)[:500]
        finally:
            Path(script_path).unlink(missing_ok=True)
            Path(output_path).unlink(missing_ok=True)
        return result

    def analyze(
        self, package: str, version: str, wheel_path: Path | None = None
    ) -> TraceResult:
        """Deprecated alias for :meth:`trace`."""
        warnings.warn(
            "ImportTracer.analyze() is deprecated; use ImportTracer.trace().",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.trace(package, version, wheel_path)

    def _restricted_env(self) -> dict[str, str]:
        """Pass through only a minimal env.

        This reduces *accidental* credential exposure to the traced import. It is
        not a security control: the child can read any file the user can read.
        """
        env = {}
        for var in ["PATH", "SYSTEMROOT", "TEMP", "TMP", "HOME", "USERPROFILE",
                    "PYTHONPATH", "VIRTUAL_ENV"]:
            val = os.environ.get(var)
            if val:
                env[var] = val
        env["SEALED_TRACE"] = "1"
        env["SEALED_SANDBOX"] = "1"  # back-compat marker
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return env
