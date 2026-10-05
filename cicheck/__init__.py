"""cicheck: a security linter for non-GitHub CI pipelines."""

from __future__ import annotations

__all__ = ["scan", "__version__"]

try:
    from importlib.metadata import version as _version

    __version__ = _version("cicheck")
except Exception:
    __version__ = "0.0.0+dev"


def scan(root: str):
    """Scan a path and return a list of Finding objects."""
    from cicheck.checks import run_all
    from cicheck.discover import discover

    findings = []
    for p in discover(root):
        findings.extend(run_all(p))
    return findings
