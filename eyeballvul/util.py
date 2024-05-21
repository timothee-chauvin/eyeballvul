import hashlib
import json
import logging
import re
import shutil
import subprocess
import time
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from tempfile import mkdtemp
from urllib.parse import urlparse

from ortools.sat.python import cp_model
from typeguard import typechecked

from eyeballvul.config.config_loader import Config
from eyeballvul.exceptions import GitRuntimeError, LinguistError, RepoNotFoundError


@typechecked
def domain_occurrences(repo_urls: list[str]) -> dict[str, int]:
    """Count the occurrences of each domain in the list of repo URLs."""
    domain_occurrences: dict[str, int] = defaultdict(int)
    for repo_url in repo_urls:
        domain = get_domain(repo_url)
        domain_occurrences[domain] += 1
    return dict(sorted(domain_occurrences.items(), key=lambda item: item[1], reverse=True))


@typechecked
def get_domain(repo_url: str) -> str:
    """Get the domain of the repo URL."""
    return urlparse(repo_url).netloc


@typechecked
def repo_url_to_name(repo_url: str) -> str:
    """Get the name of the repository from the URL."""
    return Path(repo_url.replace(".git", "")).name


@typechecked
def solve_hitting_set(lists: list[list[str]], version_dates: dict[str, float]) -> list[str]:
    """Versions are returned sorted by date in ascending order, according to `version_dates`."""

    start = time.time()
    model = cp_model.CpModel()

    all_versions = {version for lst in lists for version in lst}
    version_vars = {version: model.NewBoolVar(version) for version in all_versions}

    for lst in lists:
        model.Add(sum(version_vars[version] for version in lst) >= 1)

    # Minimize the number of selected versions
    model.Minimize(sum(version_vars[version] for version in all_versions))

    solver = cp_model.CpSolver()
    status = solver.Solve(model)

    if status == cp_model.OPTIMAL:
        min_versions = sum(solver.Value(version_vars[version]) for version in all_versions)
    else:
        raise ValueError("No optimal solution found in stage 1/2.")

    # Add a constraint to fix the number of selected versions
    model.Add(sum(version_vars[version] for version in all_versions) == min_versions)

    # Maximize the sum of the selected version dates
    model.Maximize(
        sum(int(version_dates[version]) * version_vars[version] for version in all_versions)
    )

    solver = cp_model.CpSolver()
    status = solver.Solve(model)

    duration = time.time() - start

    if status == cp_model.OPTIMAL:
        hitting_set = [version for version in all_versions if solver.Value(version_vars[version])]
        logging.debug(f"Minimum hitting set: {hitting_set}")
        logging.debug(f"Optimal solution found in {duration:.2f} seconds.")
        return sorted(hitting_set, key=lambda version: version_dates[version])
    else:
        raise ValueError("No optimal solution found in stage 2/2.")


@typechecked
def get_str_weak_hash(s: str) -> str:
    return hashlib.md5(s.encode(), usedforsecurity=False).hexdigest()


@contextmanager
def temp_directory():
    """Context manager to create and clean up a temporary directory."""
    tmp_dir = mkdtemp(dir=Config.paths.workdir)
    try:
        yield tmp_dir
    finally:
        try:
            shutil.rmtree(tmp_dir)
        except Exception as e:
            logging.error(f"Failed to remove temp directory {tmp_dir}: {e}")


def extract_from_regex(regex: str, text: str) -> str:
    """Extract the first match of the regex in the text."""
    match = re.search(regex, text)
    if match is None:
        raise ValueError(f"No match found for regex {regex} in text {text}")
    return match.group(1)


@typechecked
def clone_repo(repo_url: str, repo_workdir: str) -> str:
    repo_name = repo_url_to_name(repo_url)
    repo_dir = Path(repo_workdir) / repo_name
    print(f"Cloning '{repo_name}'...")
    try:
        res = subprocess.run(
            ["git", "clone", repo_url],
            cwd=repo_workdir,
            capture_output=True,
            env={"GIT_ASKPASS": "true"},
        )
        if res.returncode != 0:
            if "remote: Repository not found" in res.stderr.decode():
                raise RepoNotFoundError(f"Repository '{repo_name}' not found.")
            else:
                # Unknown error
                raise GitRuntimeError(
                    f"Non-zero return code for git clone '{repo_name}'. stderr: {res.stderr.decode()}"
                )
    except RuntimeError:
        raise GitRuntimeError(f"Repository '{repo_name}' raised a runtime error.")
    return str(repo_dir)


@typechecked
def compute_code_sizes_at_revision(repo_dir: str, commit: str) -> tuple[dict[str, int], int]:
    """
    Get the size of each programming language in bytes (sorted in order of decreasing size), as well
    as the total number of bytes of code, at the given commit from github-linguist.

    :return: a tuple (languages, size)
    """
    # cwd is used for asdf to select the correct version of bundle
    try:
        linguist_output = subprocess.check_output(
            ["bundle", "exec", "github-linguist", "--json", "--rev", commit, repo_dir],
            cwd=Config.paths.project,
        ).decode()
    except subprocess.CalledProcessError:
        raise LinguistError()
    languages = {k: v["size"] for k, v in json.loads(linguist_output).items()}
    sorted_languages = dict(sorted(languages.items(), key=lambda item: item[1], reverse=True))
    total = sum(languages.values())
    return (sorted_languages, total)


@typechecked
def get_version_commit(repo_dir: str, version: str) -> str | None:
    """
    Get the commit hash of the given version.

    If the version isn't known to git, return None.
    """
    try:
        return (
            subprocess.check_output(
                ["git", "rev-list", "-n", "1", version], stderr=subprocess.DEVNULL, cwd=repo_dir
            )
            .decode()
            .strip()
        )
    except subprocess.CalledProcessError:
        return None


@typechecked
def get_version_date(repo_dir: str, version: str) -> float | None:
    """
    Get the commit date, as a float, of the given version.

    If the version isn't known to git, return None.
    """
    try:
        date_str = (
            subprocess.check_output(
                ["git", "log", "-1", "--format=%cI", version],
                stderr=subprocess.DEVNULL,
                cwd=repo_dir,
            )
            .decode()
            .strip()
        )
        return datetime.fromisoformat(date_str).timestamp()
    except subprocess.CalledProcessError:
        return None


@typechecked
def str_or_datetime_to_datetime(date: str | datetime) -> datetime:
    if isinstance(date, str):
        return datetime.fromisoformat(date)
    return date
