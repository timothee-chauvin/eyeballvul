import cProfile
import io
import json
import logging
import pstats
import sys
import zipfile
from datetime import datetime
from pathlib import Path

import fire
import requests
from sqlmodel import Session, SQLModel, create_engine, select
from typeguard import typechecked

from eyeballvul.config import Config
from eyeballvul.converter import Converter
from eyeballvul.models.eyeballvul import EyeballvulItem, EyeballvulRevision

logging.basicConfig(
    level=logging.INFO, format="%(levelname)s-%(process)d-%(asctime)s - %(message)s"
)


def fatal(message: str) -> None:
    """Print a message to stderr and exit with status 1."""
    print(message, file=sys.stderr)
    sys.exit(1)


class Build:
    """The group of functions used in building the eyeballvul dataset from osv.dev."""

    @staticmethod
    def download():
        """Download and extract the data from the osv.dev dataset."""
        ecosystems = Config.ecosystems
        url_template = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
        for ecosystem in ecosystems:
            destination = Config.paths.osv / ecosystem
            url = url_template.format(ecosystem=ecosystem)
            logging.info(f"Downloading data from {ecosystem}...")
            response = requests.get(url, timeout=30)
            z = zipfile.ZipFile(io.BytesIO(response.content))
            z.extractall(destination)

    @staticmethod
    def convert_one(repo_url: str) -> None:
        return Converter().convert_one(repo_url)

    @staticmethod
    def convert_all() -> None:
        return Converter().convert_all()

    @staticmethod
    def convert_range(start: int, end: int) -> None:
        return Converter().convert_range(start, end)


@typechecked
def get_by_commit(
    commit_hash: str, after: str | None = None, before: str | None = None, count: bool | None = None
):
    """
    Get the Eyeballvul items that match a commit hash.

    The commit hash must be 40 characters long.

    The list can be filtered with the optional `after` and `before` parameters, which must be ISO
    8601 dates.

    `after` is included, and `before` is excluded, i.e. the possible options are: (1) after <= date,
    (2) after <= date < before, (3) date < before.

    If the `count` parameter is set to True, the number of items is printed, instead of the items
    themselves.
    """
    if len(commit_hash) != 40:
        fatal("The commit hash must be 40 characters long.")
    engine = create_engine(f"sqlite:///{Config.paths.db}/eyeballvul.db")
    with Session(engine) as session:
        # FIXME this isn't very clean (tests if the commit hash is part of the json string of the commit array)
        # This SQL would be better, but I can't find a way to convert it to sqlalchemy:
        # SELECT r.* FROM eyeballvulitem r, JSON_EACH(r.commits) as jc WHERE jc.value = 'commit_hash';

        # type ignore used because EyeballvulItem.commits doesn't have
        # a `contains` method, but this is valid sqlalchemy.
        query = select(EyeballvulItem).where(EyeballvulItem.commits.contains(commit_hash))  # type: ignore[attr-defined]

        if after:
            start_date = datetime.fromisoformat(after)
            query = query.where(EyeballvulItem.published >= start_date)
        if before:
            end_date = datetime.fromisoformat(before)
            query = query.where(EyeballvulItem.published < end_date)

        results = session.exec(query).all()
        if count:
            print(len(results))
        else:
            results_json = [item.to_dict() for item in results]
            print(json.dumps(results_json, indent=2))


def get_projects(count: bool | None = None):
    """Get the list of repo URLs."""
    engine = create_engine(f"sqlite:///{Config.paths.db}/eyeballvul.db")
    with Session(engine) as session:
        query = select(EyeballvulItem.repo_url).distinct()
        results = session.exec(query).all()
        if count:
            print(len(results))
        else:
            print(json.dumps(results, indent=2))


def get_by_project(
    repo_url: str, after: str | None = None, before: str | None = None, count: bool | None = None
):
    """
    Get the Eyeballvul items that match a project's repo URL.

    The list can be filtered with the optional `after` and `before` parameters, which must be ISO
    8601 dates.

    `after` is included, and `before` is excluded, i.e. the possible options are: (1) after <= date,
    (2) after <= date < before, (3) date < before.

    If the `count` parameter is set to True, the number of items is printed, instead of the items
    themselves.
    """
    engine = create_engine(f"sqlite:///{Config.paths.db}/eyeballvul.db")
    with Session(engine) as session:
        query = select(EyeballvulItem).where(EyeballvulItem.repo_url == repo_url)

        if after:
            start_date = datetime.fromisoformat(after)
            query = query.where(EyeballvulItem.published >= start_date)
        if before:
            end_date = datetime.fromisoformat(before)
            query = query.where(EyeballvulItem.published < end_date)

        results = session.exec(query).all()
        results_json = [item.to_dict() for item in results]
        if count:
            print(len(results))
        else:
            print(json.dumps(results_json, indent=2))


def get_commits(
    after: str | None = None,
    before: str | None = None,
    project: str | None = None,
    count: bool | None = None,
):
    """
    Get a list of all commits that have at least one vuln within the date range.

    The list can be filtered with the optional `after` and `before` parameters, which must be ISO
    8601 dates.

    `after` is included, and `before` is excluded, i.e. the possible options are: (1) after <= date,
    (2) after <= date < before, (3) date < before.

    The list can also be filtered by the `project` parameter, a repo URL.

    If the `count` parameter is set to True, the number of commits is printed, instead of the
    commits themselves.
    """
    engine = create_engine(f"sqlite:///{Config.paths.db}/eyeballvul.db")
    with Session(engine) as session:
        query = select(EyeballvulItem)
        if project:
            query = query.where(EyeballvulItem.repo_url == project)
        if after:
            start_date = datetime.fromisoformat(after)
            query = query.where(EyeballvulItem.published >= start_date)
        if before:
            end_date = datetime.fromisoformat(before)
            query = query.where(EyeballvulItem.published < end_date)

        results = session.exec(query).all()
        commits = {commit for item in results for commit in item.commits}
        if count:
            print(len(commits))
        else:
            print(json.dumps(list(commits), indent=2))


def get_revision(commit_hash: str) -> None:
    """Get the Eyeballvul revision that matches a commit hash."""
    if len(commit_hash) != 40:
        fatal("The commit hash must be 40 characters long.")
    engine = create_engine(f"sqlite:///{Config.paths.db}/eyeballvul.db")
    with Session(engine) as session:
        query = select(EyeballvulRevision).where(EyeballvulRevision.commit == commit_hash)
        result = session.exec(query).first()
        if not result:
            fatal(f"No revision found for commit {commit_hash}.")
        else:
            result_json = result.to_dict()
            print(json.dumps(result_json, indent=2))


def json_export() -> None:
    """Export the contents of the SQL database into JSON files in the data directory."""
    if Path(Config.paths.data).exists():
        fatal(
            f"The data directory already exists at {Config.paths.data}.\n"
            "Please remove it or back it up before exporting."
        )
    for path in [Config.paths.eyeballvul_vulns, Config.paths.eyeballvul_revisions]:
        path.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{Config.paths.db}/eyeballvul.db")
    with Session(engine) as session:
        item_query = select(EyeballvulItem)
        eyeballvul_items = session.exec(item_query).all()
        for item in eyeballvul_items:
            item.log()
        revision_query = select(EyeballvulRevision)
        eyeballvul_revisions = session.exec(revision_query).all()
        for revision in eyeballvul_revisions:
            revision.log()
    print(
        f"Successfully exported {len(eyeballvul_items)} EyeballvulItems and {len(eyeballvul_revisions)} EyeballvulRevisions to {Config.paths.data}."
    )


def json_import() -> None:
    """Import the contents of the JSON files in the data directory into the SQL database."""
    if Path(Config.paths.db).exists():
        fatal(
            f"The database directory already exists at {Config.paths.db}.\n"
            "Please remove it or back it up before importing."
        )
    Path(Config.paths.db).mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{Config.paths.db}/eyeballvul.db")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        eyeballvul_item_files = list(Config.paths.eyeballvul_vulns.glob("*/*/*.json"))
        for path in eyeballvul_item_files:
            item = EyeballvulItem.from_file(path)
            session.add(item)
        eyeballvul_revision_files = list(Config.paths.eyeballvul_revisions.glob("*/*/*.json"))
        for path in eyeballvul_revision_files:
            revision = EyeballvulRevision.from_file(path)
            session.add(revision)
        session.commit()
    print(
        f"Successfully imported {len(eyeballvul_item_files)} EyeballvulItems and {len(eyeballvul_revision_files)} EyeballvulRevisions into the database at {Config.paths.db}."
    )


def main():
    fire.Fire(
        {
            "build": Build,
            "get_by_commit": get_by_commit,
            "get_by_project": get_by_project,
            "get_commits": get_commits,
            "get_projects": get_projects,
            "get_revision": get_revision,
            "json_export": json_export,
            "json_import": json_import,
        }
    )


def profile():
    pr = cProfile.Profile()
    pr.enable()
    try:
        main()
    finally:
        pr.disable()
        pr.dump_stats("profile.stats")

        p = pstats.Stats("profile.stats")
        p.sort_stats("cumtime").print_stats(50)


if __name__ == "__main__":
    main()
