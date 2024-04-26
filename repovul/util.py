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


def solve_hitting_set(lists: list[list[str]], version_dates: dict[str, str]) -> list[str]:
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
def clone_repo_with_cache(repo_url: str, tmp_dir: str) -> str:
    # Extract the repo name from the URL
    repo_name = Path(repo_url.replace(".git", "")).name

    # Check if the repo is already in the cache
    cache_dir = Path(Config.paths.repo_cache) / repo_name
    if cache_dir.exists():
        # If the repo is in the cache, update it
        logging.info(f"Updating '{repo_name}' from cache...")
        subprocess.check_call(["git", "pull"], cwd=cache_dir)
    else:
        # If the repo is not in the cache, clone it
        print(f"Cloning '{repo_name}' into cache...")
        subprocess.run(["git", "clone", repo_url], cwd=Config.paths.repo_cache)

    # Copy the updated repo from the cache to the temporary directory
    dest_dir = Path(tmp_dir) / repo_name
    logging.info(f"Copying '{repo_name}' to {dest_dir}...")
    shutil.copytree(cache_dir, dest_dir)

    return str(dest_dir)


@typechecked
def get_version_dates(versions: set[str], repo_dir: str) -> dict[str, str]:
    """Get the dates of the versions in the repository."""
    version_dates = {}
    for version in versions:
        try:
            date = (
                subprocess.check_output(["git", "log", "-1", "--format=%cI", version], cwd=repo_dir)
                .decode()
                .strip()
            )
            version_dates[version] = date
        except subprocess.CalledProcessError as e:
            logging.debug(
                f"Failed to get the date of version {version}: exit status {e.returncode}"
            )
    return version_dates
