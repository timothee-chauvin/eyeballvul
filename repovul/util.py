import hashlib
import json
import logging
import os
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

from repovul.config.config_loader import Config


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
    """Context manager to create and clean up a temporary directory, changing the current directory
    to it for the duration of the context."""
    saved_cwd = os.getcwd()
    tmp_dir = mkdtemp(dir=Config.paths.workdir)
    try:
        os.chdir(tmp_dir)
        yield tmp_dir
    finally:
        try:
            shutil.rmtree(tmp_dir)
        except Exception as e:
            logging.error(f"Failed to remove temp directory {tmp_dir}: {e}")
        finally:
            os.chdir(saved_cwd)


def extract_from_regex(regex: str, text: str) -> str:
    """Extract the first match of the regex in the text."""
    match = re.search(regex, text)
    if match is None:
        raise ValueError(f"No match found for regex {regex} in text {text}")
    return match.group(1)


@typechecked
def clone_repo_with_cache(repo_url: str) -> str:
    repo_name = repo_url_to_name(repo_url)
    # Check if the repo is already in the cache
    repo_dir = Path(Config.paths.repo_cache) / repo_name
    if repo_dir.exists():
        # If the repo is in the cache, update it
        logging.info(f"Updating '{repo_name}' from cache...")
        subprocess.check_call(
            ["git", "pull"], cwd=repo_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    else:
        # If the repo is not in the cache, clone it
        print(f"Cloning '{repo_name}' into cache...")
        subprocess.run(
            ["git", "clone", repo_url],
            cwd=Config.paths.repo_cache,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    return str(repo_dir)


@typechecked
def compute_code_sizes_at_revision(repo_dir: str, commit: str) -> tuple[dict[str, int], int]:
    """
    Get the size of each programming language in bytes (sorted in order of decreasing size), as well
    as the total number of bytes of code, at the given commit from github-linguist.

    :return: a tuple (languages, size)
    """
    # cwd is used for asdf to select the correct version of bundle
    linguist_output = subprocess.check_output(
        ["bundle", "exec", "github-linguist", "--json", "--rev", commit, repo_dir],
        cwd=Config.paths.project,
    ).decode()
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
