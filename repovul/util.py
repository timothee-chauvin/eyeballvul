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
def _solve_hitting_set(lists: list[list[str]], version_dates: dict[str, str]) -> list[str]:
    def parse_version(version: str) -> int:
        return int(datetime.fromisoformat(version_dates[version]).timestamp())

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
    model.Maximize(sum(parse_version(version) * version_vars[version] for version in all_versions))

    solver = cp_model.CpSolver()
    status = solver.Solve(model)

    duration = time.time() - start

    if status == cp_model.OPTIMAL:
        hitting_set = [version for version in all_versions if solver.Value(version_vars[version])]
        logging.debug(f"Minimum hitting set: {hitting_set}")
        logging.debug(f"Optimal solution found in {duration:.2f} seconds.")
        return hitting_set
    else:
        raise ValueError("No optimal solution found in stage 2/2.")


@typechecked
def solve_hitting_set(
    lists: list[list[str]], version_dates: dict[str, str], use_cache: bool = True
) -> list[str]:
    """
    Solve the hitting set problem.

    If `use_cache` is True, the solution is retrieved from the cache if it exists.

    In any case, the solution is saved to the cache after being computed.
    """
    sorted_lists = sorted([sorted(lst) for lst in lists])
    sorted_version_dates = sorted(version_dates.items(), key=lambda item: item[0])
    arguments_hash = get_str_weak_hash(json.dumps([sorted_lists, sorted_version_dates]))
    cache_filepath = Config.paths.hitting_set_cache / f"{arguments_hash}.json"
    if use_cache and cache_filepath.exists():
        with open(cache_filepath) as f:
            solution = json.load(f)
        logging.info(f"Hitting set solution found in cache: {solution}")
    else:
        solution = _solve_hitting_set(lists, version_dates)
        with open(cache_filepath, "w") as f:
            json.dump(solution, f)
            f.write("\n")
        logging.info("Hitting set solution saved to cache.")
    return solution


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
        subprocess.check_call(["git", "pull"], cwd=repo_dir)
    else:
        # If the repo is not in the cache, clone it
        print(f"Cloning '{repo_name}' into cache...")
        subprocess.run(["git", "clone", repo_url], cwd=Config.paths.repo_cache)

    return str(repo_dir)


@typechecked
def get_version_dates(versions: set[str], repo_dir: str) -> dict[str, str]:
    """Get the dates of the versions in the repository."""
    version_dates = {}
    for version in versions:
        try:
            date = (
                subprocess.check_output(
                    ["git", "log", "-1", "--format=%cI", version],
                    stderr=subprocess.DEVNULL,
                    cwd=repo_dir,
                )
                .decode()
                .strip()
            )
            version_dates[version] = date
        except subprocess.CalledProcessError as e:
            logging.debug(
                f"Failed to get the date of version {version}: exit status {e.returncode}"
            )
    return version_dates


@typechecked
def compute_code_sizes_at_revision(repo_dir: str, commit: str) -> dict[str, int | dict[str, int]]:
    """Get the size of each programming language in bytes (sorted in order of decreasing size), as
    well as the total number of bytes of code, at the given commit from github-linguist."""
    # cwd is used for asdf to select the correct version of bundle
    linguist_output = subprocess.check_output(
        ["bundle", "exec", "github-linguist", "--json", "--rev", commit, repo_dir],
        cwd=Config.paths.project,
    ).decode()
    languages = {k: v["size"] for k, v in json.loads(linguist_output).items()}
    sorted_languages = dict(sorted(languages.items(), key=lambda item: item[1], reverse=True))
    total = sum(languages.values())
    return {
        "languages": sorted_languages,
        "size": total,
    }


@typechecked
def tag_to_commit(tag: str) -> str:
    """Get the commit hash of the given tag."""
    return subprocess.check_output(["git", "rev-list", "-n", "1", tag]).decode().strip()
