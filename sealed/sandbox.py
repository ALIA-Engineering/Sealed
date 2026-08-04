"""Deprecated shim. The feature formerly called "behavioral sandbox" is
import-time behavioral *tracing* and lives in :mod:`sealed.tracer`.

It was never a sandbox: it provides no containment. See
:data:`sealed.tracer.NOT_A_SANDBOX_WARNING` and the :mod:`sealed.tracer`
module docstring for the documented bypasses.

This module re-exports the old names so existing code keeps working; it will be
removed in a future release.
"""

from __future__ import annotations

from sealed.tracer import (  # noqa: F401
    KNOWN_BYPASSES,
    NOT_A_SANDBOX_WARNING,
    ImportTracer,
    TracedBehavior,
    TraceResult,
)

#: Old name. The class never sandboxed anything.
BehavioralSandbox = ImportTracer
SandboxResult = TraceResult
SandboxBehavior = TracedBehavior

__all__ = [
    "BehavioralSandbox", "SandboxResult", "SandboxBehavior",
    "ImportTracer", "TraceResult", "TracedBehavior",
    "NOT_A_SANDBOX_WARNING", "KNOWN_BYPASSES",
]
