import json
import logging
import shutil
import time
from typing import cast

from sqlmodel import Session, SQLModel, create_engine
from typeguard import typechecked

from repovul.config.config_loader import Config
from repovul.models.cache import Cache
from repovul.models.osv import OSVVulnerability
from repovul.models.repovul import RepovulItem, RepovulRevision
from repovul.util import (
    clone_repo_with_cache,
    compute_code_sizes_at_revision,
    get_domain,
    get_version_dates,
    solve_hitting_set,
    tag_to_commit,
)


@typechecked
class Converter:
    """Class to perform the conversion from OSV items to Repovul items."""

    def __init__(self):
        self.cache = Cache.read()
        self.osv_items = self.get_osv_items()
        self.by_repo = self.osv_items_by_repo(self.osv_items)

    def convert_one(self, repo_url: str) -> None:
        """Convert the OSV items of a single repository to Repovul items."""
        items = self.by_repo[repo_url]
        osv_items = [OSVVulnerability(**item) for item in items]
        repovul_items, repovul_revisions = self.osv_group_to_repovul_group(osv_items)
        engine = create_engine(f"sqlite:///{Config.paths.db}/repovul.db")
        SQLModel.metadata.create_all(engine)
        with Session(engine) as session:
            for repovul_item in repovul_items:
                session.merge(repovul_item)
            for repovul_revision in repovul_revisions:
                session.merge(repovul_revision)
            session.commit()
        self.cache.write()

    def convert_all(self) -> None:
        """Convert the OSV items of all repositories to Repovul items."""
        start = time.time()
        for i, repo_url in enumerate(self.by_repo.keys()):
            logging.info(f"Processing {repo_url}...")
            self.convert_one(repo_url)
            elapsed = time.time() - start
            ETA = elapsed / (i + 1) * (len(self.by_repo) - i - 1)
            logging.info(f"({i+1}/{len(self.by_repo)}) elapsed {elapsed:.2f}s ETA {ETA:.2f}")

    @staticmethod
    def get_osv_items() -> list[dict]:
        """Get the items from the osv.dev dataset."""
        osv_path = Config.paths.osv
        items = []
        for ecosystem in Config.paths.osv.iterdir():
            for item_basename in ecosystem.iterdir():
                with open(osv_path / ecosystem / item_basename) as f:
                    item = json.load(f)
                items.append(item)
        return items

    @staticmethod
    def osv_items_by_repo(items: list[dict]) -> dict[str, list[dict]]:
        """
        Group the items from the osv.dev dataset by repository.

        Filtering out unsupported domains is done in this function.
        """
        items_by_repo: dict[str, list] = {}
        filtered_out = set()
        for item in items:
            repo_url = OSVVulnerability(**item).get_repo_url()
            if get_domain(repo_url) not in Config.supported_domains:
                filtered_out.add(repo_url)
                continue
            items_by_repo.setdefault(repo_url, []).append(item)
        logging.info(
            f"Kept {len(items_by_repo)} repos. {len(filtered_out)} unsupported repos filtered out."
        )
        return items_by_repo

    def osv_group_to_repovul_group(
        self, osv_group: list[OSVVulnerability]
    ) -> tuple[list[RepovulItem], list[RepovulRevision]]:
        """
        Convert a group of OSV items, sharing the same repo URL, to a group of Repovul items and a
        group of Repovul revisions.

        This is done by groups in order to compute the smallest set of commits that hold all the
        vulnerabilities in the group.

         OSV items that don't have any affected version, or that are marked as withdraw, are
        ignored.

        Versions that aren't found in the git repo are also ignored.
        """
        osv_group = self.filter_out_no_affected_versions(osv_group)
        osv_group = self.filter_out_withdrawn(osv_group)
        if not osv_group:
            logging.info("No OSV items with affected versions found. Skipping.")
            return [], []
        repo_url = self.get_repo_url(osv_group)
        # TODO change this
        repo_dir = clone_repo_with_cache(repo_url)
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
        hitting_set_versions = sorted(
            hitting_set_versions, key=lambda version: version_dates[version]
        )
        logging.info(f"Minimum hitting set: {hitting_set_versions}")

        repovul_items = []
        repovul_revisions = self.versions_to_repovul_revisions(
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
                severity=osv_item.severity,
                commits=[repovul_revisions[version].commit for version in concerned_versions],
            )
            repovul_items.append(repovul_item)
        repos_to_cache = [
            "https://github.com/mattermost/desktop",
            "https://github.com/blackcatdevelopment/blackcatcms",
            "https://github.com/wireshark/wireshark",
            "https://github.com/pimcore/pimcore",
            "https://gitlab.com/gitlab-org/gitlab",
        ]
        if repo_url not in repos_to_cache:
            shutil.rmtree(repo_dir)
        return repovul_items, list(repovul_revisions.values())

    @staticmethod
    def filter_out_no_affected_versions(
        osv_group: list[OSVVulnerability],
    ) -> list[OSVVulnerability]:
        """Filter out OSV items that don't have any affected version."""
        filtered = [osv_item for osv_item in osv_group if osv_item.get_affected_versions()]
        if len(filtered) < len(osv_group):
            logging.info(
                f"Filtered out {len(osv_group) - len(filtered)}/{len(osv_group)} OSV items without affected versions."
            )
        return filtered

    @staticmethod
    def filter_out_withdrawn(osv_group: list[OSVVulnerability]) -> list[OSVVulnerability]:
        """Filter out OSV items that are marked as withdrawn."""
        filtered = [osv_item for osv_item in osv_group if not osv_item.withdrawn]
        if len(filtered) < len(osv_group):
            logging.info(
                f"Filtered out {len(osv_group) - len(filtered)}/{len(osv_group)} OSV items marked as withdrawn."
            )
        return filtered

    @staticmethod
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

    @staticmethod
    def versions_to_repovul_revisions(
        versions: list[str], version_dates: dict[str, str], repo_dir: str, use_cache: bool = True
    ) -> dict[str, RepovulRevision]:
        repovul_revisions = {}
        for i, version in enumerate(versions):
            commit = tag_to_commit(repo_dir, version)
            revision_filepath = Config.paths.repovul_revisions / f"{commit}.json"
            if use_cache and revision_filepath.exists():
                logging.info(
                    f"(linguist {i+1}/{len(versions)}) Found size in cache for version {version}."
                )
                repovul_revision = RepovulRevision.from_file(
                    Config.paths.repovul_revisions / f"{commit}.json"
                )
                repovul_revisions[version] = repovul_revision
            else:
                logging.info(
                    f"(linguist {i+1}/{len(versions)}) Computing size for version {version}..."
                )
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
