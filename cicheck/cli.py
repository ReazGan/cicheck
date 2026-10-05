"""cicheck command-line entry point.

    cicheck                 scan the current directory
    cicheck path            scan a directory or a single CI file
    cicheck --min high      only high and critical findings
    cicheck --json          machine-readable output

Exit status: 0 clean, 1 findings at/above --fail-on, 2 on error.
"""

from __future__ import annotations

import json as jsonlib
import sys

import click
from rich.console import Console
from rich.text import Text

from cicheck import __version__
from cicheck.checks import run_all
from cicheck.checks.base import SEVERITY_ORDER
from cicheck.discover import discover

SEVERITY_STYLE = {"critical": "bold white on red", "high": "bold red",
                  "medium": "bold yellow", "low": "cyan"}
PLATFORM = {"gitlab": "GitLab CI", "circleci": "CircleCI", "azure": "Azure Pipelines",
            "bitbucket": "Bitbucket", "drone": "Drone", "travis": "Travis"}
_LEVELS = ("low", "medium", "high", "critical")


@click.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--min", "min_sev", type=click.Choice(_LEVELS), default="low",
              help="Lowest severity to show.")
@click.option("--fail-on", type=click.Choice(_LEVELS), default="high",
              help="Lowest severity that makes the exit code 1.")
@click.option("--json", "json_out", is_flag=True, help="Print findings as JSON.")
@click.option("--no-color", is_flag=True, help="Disable colored output.")
@click.version_option(__version__, package_name="cicheck", prog_name="cicheck")
def main(path, min_sev, fail_on, json_out, no_color):
    """Security linter for GitLab CI, CircleCI, Azure, Bitbucket, Drone and Travis."""
    console = Console(no_color=no_color, highlight=False)
    try:
        pipelines = discover(path)
        findings = []
        for p in pipelines:
            findings.extend(run_all(p))
    except Exception as exc:  # noqa: BLE001
        click.echo(f"cicheck: error while scanning: {exc}", err=True)
        sys.exit(2)

    shown = [f for f in findings if SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[min_sev]]
    shown.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.path, f.line or 0))
    worst = min((SEVERITY_ORDER[f.severity] for f in findings), default=99)
    failed = worst <= SEVERITY_ORDER[fail_on]

    if json_out:
        click.echo(jsonlib.dumps({
            "version": __version__,
            "files_scanned": len(pipelines),
            "findings": [f.to_dict() for f in shown],
        }, indent=2))
    else:
        _report(console, pipelines, shown, findings)

    sys.exit(1 if failed else 0)


def _report(console, pipelines, shown, all_findings):
    console.print(Text("cicheck ", style="bold").append(__version__, style="dim"))
    if not pipelines:
        console.print("no CI config files found "
                      "(looked for .gitlab-ci.yml, .circleci/config.yml, "
                      "azure-pipelines.yml, bitbucket-pipelines.yml, ...)")
        return

    plat = {p.path: p.platform for p in pipelines}
    by_path: dict[str, list] = {}
    for f in shown:
        by_path.setdefault(f.path, []).append(f)

    for path in sorted(by_path):
        console.print()
        console.print(Text(path, style="bold").append(
            f"  {PLATFORM.get(plat.get(path, ''), '')}", style="dim"))
        for f in by_path[path]:
            tag = f" {f.severity.upper()} "
            head = Text("  ").append(tag, style=SEVERITY_STYLE[f.severity])
            head.append("  ").append(f.title).append(f"  {f.check}", style="dim")
            console.print(head)
            loc = path + (f":{f.line}" if f.line else "")
            console.print(Text("      " + loc, style="dim"))
            for line in _wrap(f.description, 84):
                console.print(Text("      " + line, style="dim"))

    counts = {lvl: 0 for lvl in _LEVELS}
    for f in all_findings:
        counts[f.severity] += 1
    console.print()
    n = len(pipelines)
    console.print(f"{n} CI file{'s' if n != 1 else ''} scanned")
    if not all_findings:
        console.print(Text("clean, no CI security issues found", style="green"))
        return
    summary = "  ".join(f"{counts[l]} {l}" for l in reversed(_LEVELS) if counts[l])
    worst = min(all_findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity
    console.print(Text(summary, style=SEVERITY_STYLE[worst]))


def _wrap(text, width):
    words, lines, line = text.split(), [], ""
    for w in words:
        if line and len(line) + 1 + len(w) > width:
            lines.append(line)
            line = ""
        line = f"{line} {w}".strip()
    if line:
        lines.append(line)
    return lines


if __name__ == "__main__":
    main()
