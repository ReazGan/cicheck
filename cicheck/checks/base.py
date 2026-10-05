"""Shared types for cicheck."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["low", "medium", "high", "critical"]
SEVERITY_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Pipeline:
    """One CI config file."""

    path: str          # forward-slash path shown to the user
    platform: str      # gitlab | circleci | azure | bitbucket | drone | travis
    text: str          # raw file contents
    data: Any          # parsed YAML (dict/list), or None if it would not parse


@dataclass
class Finding:
    check: str
    title: str
    description: str
    severity: Severity
    path: str
    line: int | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"check": self.check, "title": self.title,
                               "severity": self.severity, "path": self.path}
        if self.line is not None:
            out["line"] = self.line
        out["description"] = self.description
        if self.evidence:
            out["evidence"] = self.evidence
        return out


def line_of(text: str, needle: str) -> int | None:
    """1-based line of the first line containing needle, or None."""
    for i, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return i
    return None
