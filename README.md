# cicheck

[![CI](https://github.com/ReazGan/cicheck/actions/workflows/ci.yml/badge.svg)](https://github.com/ReazGan/cicheck/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/cicheck)](https://pypi.org/project/cicheck/)

A security linter for the CI platforms that don't have one.

GitHub Actions has [zizmor](https://github.com/woodruffw/zizmor). Everyone else,
GitLab CI, CircleCI, Azure Pipelines, Bitbucket, Drone and Travis, has the same
classes of bug and no equivalent tool. cicheck reads those pipeline files and
flags the common ones: hard-coded secrets, unpinned images, shell injection
through branch names and commit messages, `curl | bash`, and a Docker socket
mounted into the job.

Runs offline. No API calls, nothing leaves your machine.

![cicheck flagging shell injection, an unpinned image and a mounted docker socket](https://raw.githubusercontent.com/ReazGan/cicheck/main/docs/screenshot.svg)

## Install

```
pip install cicheck
```

## Usage

```
cicheck                  scan the current directory
cicheck path             scan a directory or a single CI file
cicheck --min high       only high and critical findings
cicheck --json           machine-readable output
```

Exit status is `0` when clean, `1` when there is a finding at or above the fail
level (`--fail-on`, default `high`), and `2` on error.

### pre-commit

```yaml
repos:
  - repo: https://github.com/ReazGan/cicheck
    rev: v0.1.0
    hooks:
      - id: cicheck
```

### GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: ReazGan/cicheck@v0.1.0
  with:
    fail-on: high
```

## What it checks

| Check | Severity | What it finds |
|-------|----------|---------------|
| `hardcoded-secret` | critical | A real-looking credential written into the pipeline file. |
| `shell-injection` | high | A branch name, commit message or MR/PR title interpolated into a shell command. |
| `docker-socket` | high | `/var/run/docker.sock` mounted into a job (root on the runner). |
| `unpinned-image` | medium | A container image with no fixed tag, or `:latest`. |
| `curl-pipe-shell` | medium | A downloaded script piped straight into a shell. |

Covers `.gitlab-ci.yml` (and `.gitlab/**`), `.circleci/config.yml`,
`azure-pipelines.yml`, `bitbucket-pipelines.yml`, `.drone.yml` and `.travis.yml`.
Injection and `curl | bash` are only checked inside actual script blocks, so
`rules:`/`if:` conditions and variable definitions don't cause noise.

## License

MIT
