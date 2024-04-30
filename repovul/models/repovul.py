import logging
import os
from typing import cast

from pydantic import BaseModel
from typeguard import typechecked

from repovul.models.osv import OSVVulnerability
from repovul.util import (
    clone_repo_with_cache,
    compute_code_sizes_at_revision,
    get_version_dates,
    solve_hitting_set,
    tag_to_commit,
    temp_directory,
)


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
    # Inferred from osv.dev and visiting the repo.
    commits: list[str]
    commit_dates: list[str]
    # Computed here.
    repo_languages: list[dict[str, int]]
    repo_sizes: list[int]


@typechecked
def osv_group_to_repovul_group(osv_group: list[OSVVulnerability]) -> list[RepovulItem]:
    """
    Convert a group of OSV items, sharing the same repo URL, to a group of Repovul items.

    This is done by groups in order to compute the smallest set of commits that hold all the
    vulnerabilities in the group.

    OSV items that don't have any affected version are ignored.

    Versions that aren't found in the git repo are also ignored.
    """
    # Filter out the OSV items that don't have any affected version.
    osv_group_new = [osv_item for osv_item in osv_group if osv_item.get_affected_versions()]
    if len(osv_group_new) < len(osv_group):
        logging.info(
            f"Filtered out {len(osv_group) - len(osv_group_new)}/{len(osv_group)} OSV items without affected versions."
        )
    osv_group = osv_group_new
    repo_url = osv_group[0].get_repo_url()
    if any(osv_item.get_repo_url() != repo_url for osv_item in osv_group):
        raise ValueError("All OSV items in the group must have the same repo URL.")
    with temp_directory() as tmp_dir:
        repo_dir = clone_repo_with_cache(repo_url, tmp_dir)
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
            all_versions -= missing_versions
        hitting_set_versions = solve_hitting_set(
            lists=list(affected_versions_by_item.values()),
            version_dates=version_dates,
        )
        hitting_set_versions = sorted(
            hitting_set_versions, key=lambda version: version_dates[version]
        )
        logging.info(f"Minimum hitting set: {hitting_set_versions}")

        # Map versions to commits
        version_commit_map = {version: tag_to_commit(version) for version in hitting_set_versions}

        # Compute sizes
        repo_languages = []
        repo_sizes = []
        for version in hitting_set_versions:
            languages_and_size = compute_code_sizes_at_revision(
                repo_dir, version_commit_map[version]
            )
            repo_languages.append(languages_and_size["languages"])
            repo_sizes.append(languages_and_size["size"])
        repovul_items = []
        for osv_item in osv_group:
            concerned_versions = [
                version
                for version in hitting_set_versions
                if version in cast(list[str], osv_item.get_affected_versions())
            ]
            commits = [version_commit_map[version] for version in concerned_versions]
            commit_dates = [version_dates[version] for version in concerned_versions]
            repovul_item = RepovulItem(
                id=osv_item.id,
                published=osv_item.published,
                modified=osv_item.modified,
                details=osv_item.details,
                summary=osv_item.summary,
                repo_url=osv_item.get_repo_url(),
                commits=commits,
                commit_dates=commit_dates,
                repo_languages=repo_languages,
                repo_sizes=repo_sizes,
            )
            repovul_items.append(repovul_item)
        return repovul_items
