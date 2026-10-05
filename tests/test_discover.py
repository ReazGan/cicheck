from __future__ import annotations

from cicheck.discover import classify, discover


def test_classify():
    assert classify(".gitlab-ci.yml") == "gitlab"
    assert classify("sub/.gitlab-ci.yml") == "gitlab"
    assert classify(".circleci/config.yml") == "circleci"
    assert classify("azure-pipelines.yml") == "azure"
    assert classify("bitbucket-pipelines.yml") == "bitbucket"
    assert classify(".drone.yml") == "drone"
    assert classify(".travis.yml") == "travis"
    assert classify(".gitlab/ci/build.yml") == "gitlab"
    assert classify("README.md") is None
    assert classify("config.yml") is None


def test_discover(tmp_path):
    (tmp_path / ".gitlab-ci.yml").write_text("image: node:latest\n", encoding="utf-8")
    cc = tmp_path / ".circleci"
    cc.mkdir()
    (cc / "config.yml").write_text("version: 2.1\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("hi", encoding="utf-8")
    found = {(p.path, p.platform) for p in discover(str(tmp_path))}
    assert found == {(".gitlab-ci.yml", "gitlab"), (".circleci/config.yml", "circleci")}


def test_single_file(tmp_path):
    f = tmp_path / ".gitlab-ci.yml"
    f.write_text("image: python\n", encoding="utf-8")
    assert len(discover(str(f))) == 1


def test_bad_yaml_does_not_crash(tmp_path):
    (tmp_path / ".gitlab-ci.yml").write_text("key: : : [unbalanced\n", encoding="utf-8")
    pipelines = discover(str(tmp_path))
    assert len(pipelines) == 1 and pipelines[0].data is None


def test_custom_tags_do_not_crash(tmp_path):
    # CircleCI / Azure use custom YAML tags.
    (tmp_path / ".circleci" ).mkdir()
    (tmp_path / ".circleci" / "config.yml").write_text(
        "steps:\n  - run: !reference [commands, build]\n", encoding="utf-8")
    pipelines = discover(str(tmp_path))
    assert len(pipelines) == 1
