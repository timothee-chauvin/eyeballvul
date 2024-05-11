import json
import logging
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import cast

from sqlalchemy import delete
from sqlmodel import Session, SQLModel, create_engine, select
from typeguard import typechecked

from repovul.config.config_loader import Config
from repovul.exceptions import LinguistError, RepoNotFoundError
from repovul.models.cache import Cache, CacheItem
from repovul.models.osv import OSVVulnerability
from repovul.models.repovul import RepovulItem, RepovulRevision
from repovul.util import (
    clone_repo,
    compute_code_sizes_at_revision,
    get_domain,
    get_str_weak_hash,
    get_version_commit,
    get_version_date,
    solve_hitting_set,
    temp_directory,
)


@typechecked
class Converter:
    """Class to perform the conversion from OSV items to Repovul items."""

    def __init__(self):
        self.cache = Cache.read()
        self.osv_items = self.get_osv_items()
        self.by_repo = self.osv_items_by_repo(self.osv_items)
        Path(Config.paths.db).mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(f"sqlite:///{Config.paths.db}/repovul.db")
        SQLModel.metadata.create_all(self.engine)

    @staticmethod
    def convert_one_inner(
        repo_url: str,
        osv_items: list[OSVVulnerability],
        cache: CacheItem,
        existing_revisions: list[RepovulRevision],
    ) -> tuple[list[RepovulItem], list[RepovulRevision], CacheItem]:
        """
        Convert the OSV items of a single repository to Repovul items.

        The CacheItem corresponding to this repo URL, as well as any existing RepovulRevisions, are
        given as input to enable caching.

        Returns a tuple of: - a list of RepovulItems - a list of RepovulRevisions - the updated
        cache
        """
        try:
            with temp_directory() as repo_workdir:
                return Converter.osv_group_to_repovul_group(
                    repo_url, repo_workdir, osv_items, cache, existing_revisions
                )
        except RepoNotFoundError:
            logging.warning(f"Repo {repo_url} not found. Skipping.")
            return [], [], cache
        except LinguistError:
            logging.warning(f"Error computing code sizes for {repo_url}. Skipping.")
            return [], [], cache

    def prepare_arguments(
        self, repo_urls: list[str]
    ) -> list[tuple[str, list[OSVVulnerability], CacheItem, list[RepovulRevision]]]:
        logging.info("Preparing arguments...")
        to_compute_args = []
        time_start = time.time()
        for repo_url in repo_urls:
            osv_items_dict = self.by_repo[repo_url]
            osv_items = [OSVVulnerability(**item) for item in osv_items_dict]
            self.cache.initialize(repo_url)
            cache = self.cache[repo_url]
            with Session(self.engine) as session:
                existing_revisions = list(
                    session.exec(
                        select(RepovulRevision).where(RepovulRevision.repo_url == repo_url)
                    ).all()
                )
            to_compute_args.append((repo_url, osv_items, cache, existing_revisions))
        duration = time.time() - time_start
        logging.info(f"Arguments prepared for {len(repo_urls)} repos in {duration:.2f}s.")
        return to_compute_args

    def convert_list(self, repo_urls: list[str]) -> None:
        to_compute_args = self.prepare_arguments(repo_urls)

        logging.info("Computing in parallel...")
        time_start = time.time()
        with ProcessPoolExecutor() as executor:
            futures_to_repo_urls = {
                executor.submit(Converter.convert_one_inner, *args): args[0]
                for args in to_compute_args
            }

            for i, future in enumerate(as_completed(futures_to_repo_urls)):
                repo_url = futures_to_repo_urls[future]
                maybe_exception = future.exception()
                if maybe_exception:
                    logging.error(f"Error processing {repo_url}: {maybe_exception}")
                    executor.shutdown(wait=False, cancel_futures=True)
                    raise maybe_exception
                repovul_items, repovul_revisions, cache = future.result()
                with Session(self.engine) as session:
                    # First remove all the items for this repo URL
                    # Using type ignore because of a limitation of sqlmodel: https://github.com/tiangolo/sqlmodel/discussions/831
                    delete_items = delete(RepovulItem).where(RepovulItem.repo_url == repo_url)  # type: ignore[arg-type]
                    session.exec(delete_items)  # type: ignore[call-overload]
                    delete_revisions = delete(RepovulRevision).where(
                        RepovulRevision.repo_url == repo_url  # type: ignore[arg-type]
                    )
                    session.exec(delete_revisions)  # type: ignore[call-overload]
                    for item in repovul_items:
                        session.add(item)
                    for revision in repovul_revisions:
                        session.add(revision)
                    session.commit()
                if cache != self.cache[repo_url]:
                    self.cache[repo_url] = cache
                    self.cache.write()
                elapsed = time.time() - time_start
                ETA = elapsed / (i + 1) * (len(repo_urls) - i - 1)
                logging.info(
                    f"({i+1}/{len(repo_urls)}) elapsed {elapsed:.2f}s ETA {ETA:.2f}, finished processing {repo_url}"
                )

    def convert_one(self, repo_url: str) -> None:
        """
        Convert the OSV items of a single repository to Repovul items.

        Top-level function.
        """
        return self.convert_list([repo_url])

    def convert_all(self) -> None:
        """Convert the OSV items of all repositories to Repovul items."""
        repo_urls = sorted(self.by_repo.keys())
        self.convert_list(repo_urls)

    def convert_range(self, start: int, end: int) -> None:
        """Convert the OSV items of a range of repositories to Repovul items."""
        repo_urls = sorted(self.by_repo.keys())[start:end]
        self.convert_list(repo_urls)

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

    @staticmethod
    def osv_group_to_repovul_group(
        repo_url: str,
        repo_workdir: str,
        osv_group: list[OSVVulnerability],
        cache: CacheItem,
        existing_revisions: list[RepovulRevision],
    ) -> tuple[list[RepovulItem], list[RepovulRevision], CacheItem]:
        """
        Convert a group of OSV items, sharing the same repo URL, to a group of Repovul items and a
        group of Repovul revisions.

        OSV items that don't have any affected version, or that are marked as withdrawn, are
        ignored.

        Versions that aren't found in the git repo are also ignored.
        """
        osv_group = Converter.filter_out_no_affected_versions(osv_group)
        osv_group = Converter.filter_out_withdrawn(osv_group)
        if not osv_group:
            logging.info("No OSV items with affected versions found. Skipping.")
            return [], [], cache
        # For each affected version in each OSV item, find the corresponding commit and its date.
        # This will allow to sort versions chronologically, to use as a constraint
        # in the hitting set solver.
        affected_versions_by_item: dict[str, list[str]] = {
            osv_item.id: cast(list[str], osv_item.get_affected_versions()) for osv_item in osv_group
        }
        all_versions = {version for lst in affected_versions_by_item.values() for version in lst}
        repo_dir = None  # don't clone the repo yet, in case it's not needed
        repo_dir, versions_info, cache = Converter.get_versions_info_with_cache(
            repo_url, repo_workdir, all_versions, repo_dir, cache
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
                return [], [], cache
        version_dates: dict[str, float] = {}
        for version in versions_info:
            version_info = versions_info[version]
            if version_info:
                version_dates[version] = version_info[1]
        hitting_set_versions, cache = Converter.solve_hitting_set_with_cache(
            lists=list(affected_versions_by_item.values()),
            version_dates=version_dates,
            cache=cache,
        )
        logging.info(f"Minimum hitting set: {hitting_set_versions}")

        repovul_items = []
        repo_dir, repovul_revisions = Converter.versions_to_repovul_revisions_with_cache(
            hitting_set_versions,
            versions_info,
            repo_url,
            repo_workdir,
            repo_dir,
            existing_revisions,
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
        return repovul_items, list(repovul_revisions.values()), cache

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
    def get_versions_info_with_cache(
        repo_url: str, repo_workdir: str, versions: set[str], repo_dir: str | None, cache: CacheItem
    ) -> tuple[str | None, dict[str, tuple[str, float] | None], CacheItem]:
        """Get the commit hash and date for each version in the repository, using the cache if it's
        already known."""
        versions_info = {}
        for version in versions:
            repo_dir, rest, cache = Converter.get_version_info_with_cache(
                repo_url, repo_workdir, version, repo_dir, cache
            )
            # rest is either None, or a tuple (commit_hash, date)
            versions_info[version] = rest
        return repo_dir, versions_info, cache

    @staticmethod
    def get_version_info_with_cache(
        repo_url: str, repo_workdir: str, version: str, repo_dir: str | None, cache: CacheItem
    ) -> tuple[str | None, tuple[str, float] | None, CacheItem]:
        """
        Get the commit hash and date for a version in the repository, using the cache if it's
        already known.

        Return None if the version isn't known to git.
        """
        if version in cache.versions_info:
            return repo_dir, cache.versions_info[version], cache
        else:
            if not repo_dir:
                logging.info("At least one version not found in cache. Cloning.")
                repo_dir = clone_repo(repo_url, repo_workdir)
            commit = get_version_commit(repo_dir, version)
            date = get_version_date(repo_dir, version)
            if commit is None or date is None:
                version_info = None
            else:
                version_info = (commit, date)
            cache.versions_info[version] = version_info
        return repo_dir, version_info, cache

    @staticmethod
    def process_new_version(
        version: str,
        version_info: tuple[str, float],
        repo_url: str,
        repo_dir: str,
    ) -> RepovulRevision:
        logging.info(f"Computing size for version '{version}'...")
        if not version_info:
            raise ValueError(f"Empty version info passed for {repo_url}")
        commit, date = version_info
        languages, size = compute_code_sizes_at_revision(repo_dir, commit)
        return RepovulRevision(
            commit=commit,
            repo_url=repo_url,
            date=datetime.fromtimestamp(date),
            languages=languages,
            size=size,
        )

    @staticmethod
    def versions_to_repovul_revisions_with_cache(
        versions: list[str],
        versions_info: dict[str, tuple[str, float] | None],
        repo_url: str,
        repo_workdir: str,
        repo_dir: str | None,
        existing_revisions: list[RepovulRevision],
    ) -> tuple[str | None, dict[str, RepovulRevision]]:
        # Convert existing_revisions into a mapping from version to revision.
        commit_to_existing_revision = {revision.commit: revision for revision in existing_revisions}
        version_to_existing_revision: dict[str, RepovulRevision] = {}
        for version in versions:
            version_info = versions_info[version]
            if version_info:
                commit, _ = version_info
                if commit in commit_to_existing_revision:
                    version_to_existing_revision[version] = commit_to_existing_revision[commit]

        if len(version_to_existing_revision) == len(versions):
            return repo_dir, version_to_existing_revision
        # Compute sizes for the yet unknown versions.
        if not repo_dir:
            repo_dir = clone_repo(repo_url, repo_workdir)
        unknown_versions = [
            version for version in versions if version not in version_to_existing_revision
        ]
        new_revisions = {}
        for version in unknown_versions:
            version_info = versions_info[version]
            if not version_info:
                raise ValueError(f"Empty version info passed for {repo_url}")
            new_revisions[version] = Converter.process_new_version(
                version, version_info, repo_url, repo_dir
            )
        return repo_dir, {**version_to_existing_revision, **new_revisions}

    @staticmethod
    def solve_hitting_set_with_cache(
        lists: list[list[str]],
        version_dates: dict[str, float],
        cache: CacheItem,
    ) -> tuple[list[str], CacheItem]:
        """
        Solve the hitting set problem, or retrieve the solution from the cache if it has already
        been computed.

        Return the possibly updated cache.
        """
        sorted_lists = sorted([sorted(lst) for lst in lists])
        sorted_version_dates = sorted(version_dates.items(), key=lambda item: item[0])
        arguments_hash = get_str_weak_hash(json.dumps([sorted_lists, sorted_version_dates]))

        if arguments_hash in cache.hitting_set_results:
            solution = cache.hitting_set_results[arguments_hash]
            logging.info("Hitting set solution found in cache.")
        else:
            solution = solve_hitting_set(lists, version_dates)
            cache.hitting_set_results[arguments_hash] = solution
        return solution, cache
