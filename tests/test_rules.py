from __future__ import annotations

import pytest

from cicheck.checks import run_all
from cicheck.checks.base import Pipeline


def scan(text, platform="gitlab"):
    import yaml
    try:
        data = yaml.safe_load(text)
    except Exception:
        data = None
    return run_all(Pipeline(path=".gitlab-ci.yml", platform=platform, text=text, data=data))


def checks(text, **kw):
    return {f.check for f in scan(text, **kw)}


def test_hardcoded_secret_flagged():
    text = "job:\n  script:\n    - deploy --token=ghp_" + "a" * 36 + "\n"
    assert "hardcoded-secret" in checks(text)


def test_private_key_flagged():
    text = 'job:\n  variables:\n    KEY: "-----BEGIN RSA PRIVATE KEY-----"\n'
    assert "hardcoded-secret" in checks(text)


def test_unpinned_latest_image_flagged():
    assert "unpinned-image" in checks("image: node:latest\njob:\n  script: [echo hi]\n")


def test_untagged_image_flagged():
    assert "unpinned-image" in checks("image: python\njob:\n  script: [echo hi]\n")


def test_pinned_image_is_clean():
    assert "unpinned-image" not in checks("image: node:18.19.0\njob:\n  script: [echo hi]\n")


def test_digest_pinned_image_is_clean():
    assert "unpinned-image" not in checks("image: node@sha256:" + "a" * 64 + "\njob:\n  script: [x]\n")


def test_variable_image_is_clean():
    assert "unpinned-image" not in checks("image: $CI_REGISTRY/app\njob:\n  script: [x]\n")


def test_curl_pipe_shell_flagged():
    text = "job:\n  script:\n    - curl -fsSL https://x.sh | bash\n"
    assert "curl-pipe-shell" in checks(text)


def test_shell_injection_flagged():
    text = 'job:\n  script:\n    - echo "building $CI_COMMIT_MESSAGE"\n'
    assert "shell-injection" in checks(text)


def test_mr_title_injection_flagged():
    text = "job:\n  script:\n    - ./build.sh ${CI_MERGE_REQUEST_TITLE}\n"
    assert "shell-injection" in checks(text)


def test_docker_socket_flagged():
    text = "job:\n  volumes:\n    - /var/run/docker.sock:/var/run/docker.sock\n"
    assert "docker-socket" in checks(text)


BENIGN = [
    "image: node:18.19.0\njob:\n  script:\n    - npm ci\n    - npm test\n",
    "variables:\n  NODE_ENV: production\njob:\n  script:\n    - echo \"$MY_SAFE_VAR\"\n",
    "job:\n  script:\n    - pip install -r requirements.txt\n    - pytest\n",
    "stages: [test]\ntest:\n  image: python:3.12-slim\n  script: [pytest -q]\n",
]


@pytest.mark.parametrize("text", BENIGN)
def test_benign_pipeline_is_clean(text):
    assert scan(text) == []
