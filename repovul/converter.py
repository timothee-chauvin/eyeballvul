import json
import logging
import shutil
import time
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime
from typing import cast

from sqlmodel import Session, SQLModel, create_engine, select
from typeguard import typechecked

from repovul.config.config_loader import Config
from repovul.models.cache import Cache
from repovul.models.osv import OSVVulnerability
from repovul.models.repovul import RepovulItem, RepovulRevision
from repovul.util import (
    clone_repo_with_cache,
    compute_code_sizes_at_revision,
    get_domain,
    get_str_weak_hash,
    get_version_commit,
    get_version_date,
    solve_hitting_set,
)


@typechecked
class Converter:
    """Class to perform the conversion from OSV items to Repovul items."""

    def __init__(self):
        self.cache = Cache.read()
        self.osv_items = self.get_osv_items()
        self.by_repo = self.osv_items_by_repo(self.osv_items)
        self.engine = create_engine(f"sqlite:///{Config.paths.db}/repovul.db")
        SQLModel.metadata.create_all(self.engine)

    def convert_one(self, repo_url: str) -> None:
        """Convert the OSV items of a single repository to Repovul items."""
        self.cache.initialize(repo_url)
        items = self.by_repo[repo_url]
        osv_items = [OSVVulnerability(**item) for item in items]
        repovul_items, repovul_revisions = self.osv_group_to_repovul_group(osv_items)
        with Session(self.engine) as session:
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

        OSV items that don't have any affected version, or that are marked as withdrawn, are
        ignored.

        Versions that aren't found in the git repo are also ignored.
        """
        osv_group = self.filter_out_no_affected_versions(osv_group)
        osv_group = self.filter_out_withdrawn(osv_group)
        if not osv_group:
            logging.info("No OSV items with affected versions found. Skipping.")
            return [], []
        repo_url = self.get_repo_url(osv_group)
        # For each affected version in each OSV item, find the corresponding commit and its date.
        # This will allow to sort versions chronologically, to use as a constraint
        # in the hitting set solver.
        affected_versions_by_item: dict[str, list[str]] = {
            osv_item.id: cast(list[str], osv_item.get_affected_versions()) for osv_item in osv_group
        }
        all_versions = {version for lst in affected_versions_by_item.values() for version in lst}
        repo_dir = None  # don't clone the repo yet, in case it's not needed
        repo_dir, versions_info = self.get_versions_info_with_cache(
            repo_url, all_versions, repo_dir
        )
        # Some versions may not have been found by git. Filter them out of our current data structures.
        unknown_versions = {v for v in versions_info if not versions_info[v]}
        if unknown_versions:
            logging.info(
                f"Filtered out {len(unknown_versions)}/{len(all_versions)} versions as not found by git: {unknown_versions}"
            )
            for item_id, affected_versions in affected_versions_by_item.items():
                affected_versions_by_item[item_id] = [
                    version for version in affected_versions if version not in unknown_versions
                ]
            # Filter out possible empty lists
            affected_versions_by_item = {
                item_id: affected_versions
                for item_id, affected_versions in affected_versions_by_item.items()
                if affected_versions
            }
            all_versions -= unknown_versions
            if not all_versions:
                logging.info("No valid versions found. Skipping.")
                return [], []
        version_dates: dict[str, float] = {}
        for version in versions_info:
            version_info = versions_info[version]
            if version_info:
                version_dates[version] = version_info[1]
        hitting_set_versions = self.solve_hitting_set_with_cache(
            repo_url=repo_url,
            lists=list(affected_versions_by_item.values()),
            version_dates=version_dates,
        )
        logging.info(f"Minimum hitting set: {hitting_set_versions}")

        repovul_items = []
        repovul_revisions = self.versions_to_repovul_revisions_with_cache(
            hitting_set_versions, versions_info, repo_url, repo_dir
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
        if repo_dir and repo_url not in repos_to_cache:
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

    def get_versions_info_with_cache(
        self, repo_url: str, versions: set[str], repo_dir: str | None
    ) -> tuple[str | None, dict[str, tuple[str, float] | None]]:
        """Get the commit hash and date for each version in the repository, using the cache if it's
        already known."""
        versions_info = {}
        for version in versions:
            repo_dir, rest = self.get_version_info_with_cache(repo_url, version, repo_dir)
            # rest is either None, or a tuple (commit_hash, date)
            versions_info[version] = rest
        return repo_dir, versions_info

    def get_version_info_with_cache(
        self, repo_url: str, version: str, repo_dir: str | None
    ) -> tuple[str | None, tuple[str, float] | None]:
        """
        Get the commit hash and date for a version in the repository, using the cache if it's
        already known.

        Return None if the version isn't known to git.
        """
        if version in self.cache[repo_url].versions_info:
            return repo_dir, self.cache[repo_url].versions_info[version]
        else:
            if not repo_dir:
                logging.info("At least one version not found in cache. Cloning.")
                repo_dir = clone_repo_with_cache(repo_url)
            commit = get_version_commit(repo_dir, version)
            date = get_version_date(repo_dir, version)
            if commit is None or date is None:
                version_info = None
            else:
                version_info = (commit, date)
            self.cache[repo_url].versions_info[version] = version_info
        return repo_dir, version_info

    def get_existing_revisions(
        self, versions: list[str], versions_info: dict[str, tuple[str, float] | None]
    ) -> dict[str, RepovulRevision]:
        existing_revisions = {}
        with Session(self.engine) as session:
            for version in versions:
                version_info = versions_info[version]
                if version_info is None:
                    raise ValueError(
                        f"Unknown version incorrectly passed to `versions_to_repovul_revisions`: '{version}."
                    )
                commit, _ = version_info
                query = select(RepovulRevision).where(RepovulRevision.commit == commit)
                existing_revision = session.exec(query).first()
                if existing_revision:
                    existing_revisions[version] = existing_revision
        logging.info(f"Found size in cache for {len(existing_revisions)}/{len(versions)} versions.")
        return existing_revisions

    @staticmethod
    def process_new_version(
        args: tuple[str, tuple[str, float], str]
    ) -> tuple[str, RepovulRevision]:
        version, version_info, repo_dir = args
        logging.info(f"Computing size for version '{version}'...")
        commit, date = version_info
        languages, size = compute_code_sizes_at_revision(repo_dir, commit)
        return version, RepovulRevision(
            commit=commit, date=datetime.fromtimestamp(date), languages=languages, size=size
        )

    def versions_to_repovul_revisions_with_cache(
        self,
        versions: list[str],
        versions_info: dict[str, tuple[str, float] | None],
        repo_url: str,
        repo_dir: str | None,
    ) -> dict[str, RepovulRevision]:
        # Proceed in two steps.
        # First, identify all the already known revisions in the database.
        existing_revisions = self.get_existing_revisions(versions, versions_info)
        if len(existing_revisions) == len(versions):
            return existing_revisions
        # Second, compute sizes in parallel for the remaining versions.
        if not repo_dir:
            repo_dir = clone_repo_with_cache(repo_url)
        to_compute_args = [
            (version, versions_info[version], repo_dir)
            for version in versions
            if version not in existing_revisions
        ]
        with ProcessPoolExecutor() as executor:
            new_revisions = executor.map(self.process_new_version, to_compute_args)
        return {**existing_revisions, **dict(new_revisions)}

    def solve_hitting_set_with_cache(
        self, repo_url: str, lists: list[list[str]], version_dates: dict[str, float]
    ) -> list[str]:
        """
        Solve the hitting set problem, or retrieve the solution from the cache if it has already
        been computed.

        The solution is saved to the cache after being computed.
        """
        sorted_lists = sorted([sorted(lst) for lst in lists])
        sorted_version_dates = sorted(version_dates.items(), key=lambda item: item[0])
        arguments_hash = get_str_weak_hash(json.dumps([sorted_lists, sorted_version_dates]))

        if arguments_hash in self.cache[repo_url].hitting_set_results:
            solution = self.cache[repo_url].hitting_set_results[arguments_hash]
            logging.info("Hitting set solution found in cache.")
        else:
            solution = solve_hitting_set(lists, version_dates)
            self.cache[repo_url].hitting_set_results[arguments_hash] = solution
            logging.info("Hitting set solution saved to cache.")
        return solution
