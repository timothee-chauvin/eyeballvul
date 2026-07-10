import subprocess

import pytest

from eyeballvul.util import get_version_commit, get_version_date


@pytest.fixture
def git_repo(tmp_path):
    subprocess.check_call(["git", "init", "-q"], cwd=tmp_path)
    subprocess.check_call(["git", "config", "user.email", "test@test"], cwd=tmp_path)
    subprocess.check_call(["git", "config", "user.name", "test"], cwd=tmp_path)
    (tmp_path / "f").write_text("x")
    subprocess.check_call(["git", "add", "f"], cwd=tmp_path)
    subprocess.check_call(
        ["git", "commit", "-q", "-m", "c"],
        cwd=tmp_path,
        env={
            "GIT_AUTHOR_DATE": "2024-01-02T03:04:05+00:00",
            "GIT_COMMITTER_DATE": "2024-01-02T03:04:05+00:00",
            "PATH": "/usr/bin:/bin",
        },
    )
    subprocess.check_call(["git", "tag", "v1.0"], cwd=tmp_path)
    return str(tmp_path)


def test_get_version_commit_and_date(git_repo):
    commit = get_version_commit(git_repo, "v1.0")
    assert commit and len(commit) == 40
    assert get_version_date(git_repo, "v1.0") == 1704164645.0


def test_unknown_version_returns_none(git_repo):
    assert get_version_commit(git_repo, "v9.9") is None
    assert get_version_date(git_repo, "v9.9") is None


def test_glob_version_returns_none(git_repo):
    # e.g. CVE-2026-7630 lists "0.6.*" as a version. git treats it as a ref
    # glob matching nothing: empty output, exit code 0.
    assert get_version_commit(git_repo, "v1.*") is None
    assert get_version_date(git_repo, "v1.*") is None
