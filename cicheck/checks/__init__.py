from __future__ import annotations

from cicheck.checks import rules
from cicheck.checks.base import SEVERITY_ORDER, Finding, Pipeline


def run_all(p: Pipeline) -> list[Finding]:
    findings = rules.check(p)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.line or 0))
    return findings
