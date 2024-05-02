import logging
import os
import shutil
from pathlib import Path
from typing import cast

from pydantic import BaseModel
from typeguard import typechecked

from repovul.config.config_loader import Config
from repovul.models.osv import OSVVulnerability
from repovul.util import (
    clone_repo_with_cache,
    compute_code_sizes_at_revision,
    get_version_dates,
    repo_url_to_name,
    solve_hitting_set,
    tag_to_commit,
)


class RepovulRevision(BaseModel):
    # Full commit hash
    commit: str
    # ISO 8601 date of the commit, e.g. "2021-09-01T00:00:00Z"
    date: str
    # Size in bytes of each programming language in the repo
    # at that commit, according to github linguist
    languages: dict[str, int]
    # Sum of all programming language sizes in bytes
    size: int

    def log(self) -> None:
        repovul_dir = Config.paths.repovul_revisions
        repovul_dir.mkdir(parents=True, exist_ok=True)
        with open(repovul_dir / f"{self.commit}.json", "w") as f:
            f.write(self.model_dump_json(indent=2))
            f.write("\n")

    @staticmethod
    def from_file(filepath: str | Path) -> "RepovulRevision":
        with open(filepath) as f:
            return RepovulRevision.model_validate_json(f.read())


class RepovulItem(BaseModel):
    # Same as in osv.dev.
    # Get it from there at https://api.osv.dev/v1/vulns/{id}
    id: str
    # Same as in osv.dev.
    published: str
    # Same as in osv.dev.
    modified: str
    # Same as in osv.dev.
    details: str
    # Same as in osv.dev.
    summary: str | None = None
    # Extracted from osv.dev.
    repo_url: str
    cwes: list[str]
    # Inferred from osv.dev and visiting the repo.
    # This maps to a list of RepovulRevision objects.
    commits: list[str]

    def log(self) -> None:
        repo_name = repo_url_to_name(self.repo_url)
        repovul_dir = Config.paths.repovul_vulns / repo_name
        repovul_dir.mkdir(parents=True, exist_ok=True)
        with open(repovul_dir / f"{self.id}.json", "w") as f:
            f.write(self.model_dump_json(indent=2, exclude_none=True))
            f.write("\n")


@typechecked
def filter_out_no_affected_versions(osv_group: list[OSVVulnerability]) -> list[OSVVulnerability]:
    """Filter out OSV items that don't have any affected version."""
    filtered = [osv_item for osv_item in osv_group if osv_item.get_affected_versions()]
    if len(filtered) < len(osv_group):
        logging.info(
            f"Filtered out {len(osv_group) - len(filtered)}/{len(osv_group)} OSV items without affected versions."
        )
    return filtered


@typechecked
def get_repo_url(osv_group: list[OSVVulnerability]) -> str:
    """
    Get the repository URL from a group of OSV items.

    All OSV items in the group must have the same repo URL.
    """
    repo_urls = {osv_item.get_repo_url() for osv_item in osv_group}
    if len(repo_urls) != 1:
        raise ValueError(
            f"All OSV items in the group must have the same repo URL. Found multiple URLs: {repo_urls}."
        )
    return repo_urls.pop()


@typechecked
def versions_to_repovul_revisions(
    versions: list[str], version_dates: dict[str, str], repo_dir: str, use_cache: bool = True
) -> dict[str, RepovulRevision]:
    repovul_revisions = {}
    for version in versions:
        commit = tag_to_commit(version)
        revision_filepath = Config.paths.repovul_revisions / f"{commit}.json"
        if use_cache and revision_filepath.exists():
            repovul_revision = RepovulRevision.from_file(
                Config.paths.repovul_revisions / f"{commit}.json"
            )
            repovul_revisions[version] = repovul_revision
        else:
            date = version_dates[version]
            languages, size = compute_code_sizes_at_revision(repo_dir, commit)
            repovul_revision = RepovulRevision(
                commit=commit,
                date=date,
                languages=languages,
                size=size,
            )
            repovul_revisions[version] = repovul_revision
    return repovul_revisions


@typechecked
def osv_group_to_repovul_group(
    osv_group: list[OSVVulnerability],
) -> tuple[list[RepovulItem], list[RepovulRevision]]:
    """
    Convert a group of OSV items, sharing the same repo URL, to a group of Repovul items and a group
    of Repovul revisions.

    This is done by groups in order to compute the smallest set of commits that hold all the
    vulnerabilities in the group.

    OSV items that don't have any affected version are ignored.

    Versions that aren't found in the git repo are also ignored.
    """
    osv_group = filter_out_no_affected_versions(osv_group)
    if not osv_group:
        logging.info("No OSV items with affected versions found. Skipping.")
        return [], []
    repo_url = get_repo_url(osv_group)
    repo_dir = clone_repo_with_cache(repo_url)
    os.chdir(repo_dir)
    # For each affected version in each OSV item, find the corresponding commit and its date.
    # This will allow to sort versions chronologically, to use as a constraint
    # in the hitting set solver.
    affected_versions_by_item: dict[str, list[str]] = {
        osv_item.id: cast(list[str], osv_item.get_affected_versions()) for osv_item in osv_group
    }
    all_versions = {version for lst in affected_versions_by_item.values() for version in lst}
    version_dates = get_version_dates(all_versions, repo_dir)
    # Some versions may be omitted due to not being found by git. Filter them out of our current data structures.
    missing_versions = all_versions - version_dates.keys()
    if missing_versions:
        logging.info(
            f"Filtering out {len(missing_versions)}/{len(all_versions)} versions as not found by git: {missing_versions}"
        )
        for item_id, affected_versions in affected_versions_by_item.items():
            affected_versions_by_item[item_id] = [
                version for version in affected_versions if version in version_dates
            ]
        # Filter out possible empty lists
        affected_versions_by_item = {
            item_id: affected_versions
            for item_id, affected_versions in affected_versions_by_item.items()
            if affected_versions
        }
        all_versions -= missing_versions
        if not all_versions:
            logging.info("No valid versions found. Skipping.")
            return [], []
    hitting_set_versions = solve_hitting_set(
        lists=list(affected_versions_by_item.values()),
        version_dates=version_dates,
    )
    hitting_set_versions = sorted(hitting_set_versions, key=lambda version: version_dates[version])
    logging.info(f"Minimum hitting set: {hitting_set_versions}")

    repovul_items = []
    repovul_revisions = versions_to_repovul_revisions(
        hitting_set_versions, version_dates, repo_dir, use_cache=True
    )
    for osv_item in osv_group:
        concerned_versions = [
            version
            for version in hitting_set_versions
            if version in cast(list[str], osv_item.get_affected_versions())
        ]
        repovul_item = RepovulItem(
            id=osv_item.id,
            published=osv_item.published,
            modified=osv_item.modified,
            details=osv_item.details,
            summary=osv_item.summary,
            repo_url=osv_item.get_repo_url(),
            cwes=osv_item.get_cwes(),
            commits=[repovul_revisions[version].commit for version in concerned_versions],
        )
        repovul_items.append(repovul_item)
    shutil.rmtree(repo_dir)
    return repovul_items, list(repovul_revisions.values())
