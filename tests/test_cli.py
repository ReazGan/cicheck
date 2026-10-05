from __future__ import annotations

import json

from click.testing import CliRunner

from cicheck.cli import main


def _w(tmp_path, name, text):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_clean_exits_zero(tmp_path):
    _w(tmp_path, ".gitlab-ci.yml", "image: node:18.19.0\njob:\n  script: [npm test]\n")
    res = CliRunner().invoke(main, [str(tmp_path), "--no-color"])
    assert res.exit_code == 0 and "clean" in res.output


def test_findings_exit_one(tmp_path):
    _w(tmp_path, ".gitlab-ci.yml", 'job:\n  script: [echo "$CI_COMMIT_MESSAGE"]\n')
    res = CliRunner().invoke(main, [str(tmp_path), "--no-color"])
    assert res.exit_code == 1 and "shell-injection" in res.output


def test_json(tmp_path):
    _w(tmp_path, ".gitlab-ci.yml", "image: node:latest\njob:\n  script: [x]\n")
    res = CliRunner().invoke(main, [str(tmp_path), "--json"])
    data = json.loads(res.output)
    assert data["files_scanned"] == 1
    assert any(f["check"] == "unpinned-image" for f in data["findings"])


def test_fail_on(tmp_path):
    _w(tmp_path, ".gitlab-ci.yml", "image: node:latest\njob:\n  script: [x]\n")  # medium only
    assert CliRunner().invoke(main, [str(tmp_path)]).exit_code == 0
    assert CliRunner().invoke(main, [str(tmp_path), "--fail-on", "medium"]).exit_code == 1


def test_empty(tmp_path):
    res = CliRunner().invoke(main, [str(tmp_path), "--no-color"])
    assert res.exit_code == 0 and "no CI config" in res.output
