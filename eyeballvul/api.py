import io
import shutil
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path

import requests
from sqlmodel import Session, SQLModel, create_engine, select
from typeguard import typechecked

from eyeballvul.config.config_loader import Config
from eyeballvul.models.eyeballvul import EyeballvulItem, EyeballvulRevision
from eyeballvul.util import str_or_datetime_to_datetime


def download_data(date: str | None = None):
    """
    Download the data from the eyeballvul_data repository.

    If `date` is provided (format: YYYY-MM-DD), the data at the specific date is downloaded. Otherwise, the latest data is downloaded. See https://github.com/timothee-chauvin/eyeballvul_data/tags for a list of valid dates.

    The data is then extracted into (by default) ~/.cache/eyeballvul/data.

    An SQLite database is instantiated from that data for faster access, in ~/.cache/eyeballvul/db.
    """
    if date is None:
        print("Fetching latest version of the data...")
        all_tags = requests.get(f"{Config.eyeballvul_data_api}/tags", timeout=30).json()
        date = all_tags[0]["name"]
    url = f"{Config.eyeballvul_data_api}/tarball/refs/tags/{date}"
    print(f"Downloading data from {url}...")
    response = requests.get(url, timeout=30)
    if response.status_code != 200:
        raise ValueError(
            f"Failed to download the data from {url}. Status code: {response.status_code}"
        )
    with tempfile.TemporaryDirectory(prefix=str(Config.paths.workdir)) as tmpdir:
        tar_file = io.BytesIO(response.content)
        tar = tarfile.open(fileobj=tar_file)
        tar_base = tar.getnames()[0].split("/")[0]
        tar.extractall(path=tmpdir, filter="data")
        tar.close()
        shutil.rmtree(Config.paths.data, ignore_errors=True)
        shutil.move(Path(tmpdir) / tar_base / "data", Config.paths.data)
    print(f"Successfully downloaded data from {url} to {Config.paths.data}.")
    print("Initializing the database from the data...")
    json_import(force=True)


@typechecked
def get_projects() -> list[str]:
    """Get the list of repo URLs."""
    engine = create_engine(f"sqlite:///{Config.paths.db}/eyeballvul.db")
    with Session(engine) as session:
        query = select(EyeballvulItem.repo_url).distinct()
        return list(session.exec(query).all())


@typechecked
def get_vulns(
    after: str | datetime | None = None,
    before: str | datetime | None = None,
    project: str | None = None,
    commit: str | None = None,
) -> list[EyeballvulItem]:
    """
    Get the Eyeballvul items that match the optional `after`, `before`, `project` and `commit`
    parameters.

    The list can be filtered with the optional `after` and `before` parameters, which must be ISO
    8601 dates.

    `after` is included, and `before` is excluded, i.e. the possible options are: (1) after <= date,
    (2) after <= date < before, (3) date < before.

    The list can also be filtered by the `project` parameter, a repo URL.

    If provided, the commit hash (`commit`) must be 40 characters long.
    """
    if commit and len(commit) != 40:
        raise ValueError("The commit hash must be 40 characters long.")
    engine = create_engine(f"sqlite:///{Config.paths.db}/eyeballvul.db")
    with Session(engine) as session:
        query = select(EyeballvulItem)

        if project:
            query = query.where(EyeballvulItem.repo_url == project)
        if after:
            start_date = str_or_datetime_to_datetime(after)
            query = query.where(EyeballvulItem.published >= start_date)
        if before:
            end_date = str_or_datetime_to_datetime(before)
            query = query.where(EyeballvulItem.published < end_date)

        # FIXME this isn't very clean (tests if the commit hash is part of the json string of the commit array)
        # This SQL would be better, but I can't find a way to convert it to sqlalchemy:
        # SELECT r.* FROM eyeballvulitem r, JSON_EACH(r.commits) as jc WHERE jc.value = 'commit_hash';

        # type ignore used because EyeballvulItem.commits doesn't have
        # a `contains` method, but this is valid sqlalchemy.
        if commit:
            query = query.where(EyeballvulItem.commits.contains(commit))  # type: ignore[attr-defined]

        return list(session.exec(query).all())


@typechecked
def get_commits(
    after: str | datetime | None = None,
    before: str | datetime | None = None,
    project: str | None = None,
) -> list[str]:
    """
    Get a list of all commits that have at least one vuln within the date range.

    The list can be filtered with the optional `after` and `before` parameters, which must be ISO
    8601 dates.

    Note that the date range doesn't apply to the commit date, but to the existence of at least one vuln associated with the commit within the date range.

    `after` is included, and `before` is excluded, i.e. the possible options are: (1) after <= date,
    (2) after <= date < before, (3) date < before.

    The list can also be filtered by the `project` parameter, a repo URL.
    """
    vulns = get_vulns(after=after, before=before, project=project)
    commits = {commit for vuln in vulns for commit in vuln.commits}
    return list(commits)


@typechecked
def get_revision(commit: str) -> EyeballvulRevision:
    """
    Get the Eyeballvul revision that matches a commit hash.

    If no revision can be found, raise a ValueError.
    """
    if len(commit) != 40:
        raise ValueError("The commit hash must be 40 characters long.")
    engine = create_engine(f"sqlite:///{Config.paths.db}/eyeballvul.db")
    with Session(engine) as session:
        query = select(EyeballvulRevision).where(EyeballvulRevision.commit == commit)
        first = session.exec(query).first()
        if first:
            return first
        else:
            raise ValueError(f"Revision with commit hash {commit} not found.")


def json_export() -> None:
    """Export the contents of the SQL database into JSON files in the data directory."""
    if Path(Config.paths.data).exists():
        raise ValueError(
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


@typechecked
def json_import(db_dest: Path = Config.paths.db, force: bool = False) -> None:
    """
    Import the contents of the JSON files in the data directory into the SQL database at `db_dest`.

    If `force` is set to True, the possibly existing database at `db_dest` will be overwritten.
    """
    if force:
        shutil.rmtree(db_dest, ignore_errors=True)
    if db_dest.exists():
        raise ValueError(
            f"The database directory already exists at {db_dest}.\n"
            "Use force=True if you wish to overwrite it."
        )
    db_dest.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{db_dest}/eyeballvul.db")
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
        f"Successfully imported {len(eyeballvul_item_files)} EyeballvulItems and {len(eyeballvul_revision_files)} EyeballvulRevisions into the database at {db_dest}."
    )
