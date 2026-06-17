"""Backend registry and discovery."""

from __future__ import annotations

from .base import Backend, RunResult
from .copilot_local import CopilotLocalBackend
from .docker import DockerBackend
from .openshell import OpenShellBackend

# Order matters only for display. The Docker backend is the runnable reference;
# the other two are adapters around external CLIs.
ALL_BACKENDS: list[type[Backend]] = [
    DockerBackend,
    OpenShellBackend,
    CopilotLocalBackend,
]


def get_backend(name: str) -> Backend:
    for cls in ALL_BACKENDS:
        if cls.name == name:
            return cls()
    raise KeyError(f"Unknown backend {name!r}. Known: {[c.name for c in ALL_BACKENDS]}")


def all_backends() -> list[Backend]:
    return [cls() for cls in ALL_BACKENDS]


def available_backends() -> list[Backend]:
    out = []
    for b in all_backends():
        ok, _ = b.is_available()
        if ok:
            out.append(b)
    return out


__all__ = [
    "Backend",
    "RunResult",
    "DockerBackend",
    "OpenShellBackend",
    "CopilotLocalBackend",
    "ALL_BACKENDS",
    "get_backend",
    "all_backends",
    "available_backends",
]
