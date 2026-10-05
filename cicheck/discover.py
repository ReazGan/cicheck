"""Find and parse non-GitHub CI config files.

GitHub Actions already has zizmor; cicheck covers the platforms that don't have
a dedicated security linter: GitLab CI, CircleCI, Azure Pipelines, Bitbucket
Pipelines, Drone and Travis.
"""

from __future__ import annotations

import os

import yaml

from cicheck.checks.base import Pipeline

MAX_SIZE = 2 * 1024 * 1024
_SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__"}

# Exact path (posix, relative) -> platform.
_EXACT = {
    ".gitlab-ci.yml": "gitlab",
    ".gitlab-ci.yaml": "gitlab",
    ".circleci/config.yml": "circleci",
    ".circleci/config.yaml": "circleci",
    "bitbucket-pipelines.yml": "bitbucket",
    "bitbucket-pipelines.yaml": "bitbucket",
    ".drone.yml": "drone",
    ".travis.yml": "travis",
}

# Basename -> platform (anywhere in the tree).
_BASENAMES = {
    "azure-pipelines.yml": "azure",
    "azure-pipelines.yaml": "azure",
}


def classify(rel_posix: str) -> str | None:
    for path, platform in _EXACT.items():
        if rel_posix == path or rel_posix.endswith("/" + path):
            return platform
    base = rel_posix.rsplit("/", 1)[-1]
    if base in _BASENAMES:
        return _BASENAMES[base]
    # GitLab include files live under .gitlab/ and end in .yml
    if "/.gitlab/" in ("/" + rel_posix) and base.endswith((".yml", ".yaml")):
        return "gitlab"
    return None


class _SafeLoader(yaml.SafeLoader):
    pass


# CI YAMLs use custom tags (CircleCI orbs, Azure !reference). Ignore unknown
# tags instead of crashing.
def _ignore_unknown(loader, suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


_SafeLoader.add_multi_constructor("!", _ignore_unknown)
_SafeLoader.add_multi_constructor("tag:", _ignore_unknown)


def discover(root: str) -> list[Pipeline]:
    root = os.path.abspath(root)
    if os.path.isfile(root):
        full = os.path.abspath(root)
        rel = "/".join(full.replace(os.sep, "/").split("/")[-3:])
        p = _load(rel, full)
        return [p] if p else []

    out: list[Pipeline] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            p = _load(rel, full)
            if p:
                out.append(p)
    out.sort(key=lambda p: p.path)
    return out


def _load(rel: str, full: str) -> Pipeline | None:
    platform = classify(rel)
    if platform is None:
        return None
    try:
        if os.path.getsize(full) > MAX_SIZE:
            return None
        text = open(full, encoding="utf-8", errors="replace").read()
    except OSError:
        return None
    try:
        data = yaml.load(text, Loader=_SafeLoader)
    except (yaml.YAMLError, Exception):  # noqa: BLE001 - never crash on bad YAML
        data = None
    return Pipeline(path=rel, platform=platform, text=text, data=data)
