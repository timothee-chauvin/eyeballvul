from datetime import datetime
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine, select
from typeguard import typechecked

from eyeballvul.config.config_loader import Config
from eyeballvul.models.eyeballvul import EyeballvulItem, EyeballvulRevision
from eyeballvul.util import str_or_datetime_to_datetime


@typechecked
def get_projects() -> list[str]:
    """Get the list of repo URLs."""
    engine = create_engine(f"sqlite:///{Config.paths.db}/eyeballvul.db")
    with Session(engine) as session:
        query = select(EyeballvulItem.repo_url).distinct()
        return list(session.exec(query).all())


@typechecked
def get_by_commit(
    commit_hash: str,
    after: str | datetime | None = None,
    before: str | datetime | None = None,
) -> list[EyeballvulItem]:
    """
    Get the Eyeballvul items that match a commit hash.

    The commit hash must be 40 characters long.

    The list can be filtered with the optional `after` and `before` parameters, which must be ISO
    8601 dates.

    `after` is included, and `before` is excluded, i.e. the possible options are: (1) after <= date,
    (2) after <= date < before, (3) date < before.
    """
    if len(commit_hash) != 40:
        raise ValueError("The commit hash must be 40 characters long.")
    engine = create_engine(f"sqlite:///{Config.paths.db}/eyeballvul.db")
    with Session(engine) as session:
        # FIXME this isn't very clean (tests if the commit hash is part of the json string of the commit array)
        # This SQL would be better, but I can't find a way to convert it to sqlalchemy:
        # SELECT r.* FROM eyeballvulitem r, JSON_EACH(r.commits) as jc WHERE jc.value = 'commit_hash';

        # type ignore used because EyeballvulItem.commits doesn't have
        # a `contains` method, but this is valid sqlalchemy.
        query = select(EyeballvulItem).where(EyeballvulItem.commits.contains(commit_hash))  # type: ignore[attr-defined]

        if after:
            start_date = str_or_datetime_to_datetime(after)
            query = query.where(EyeballvulItem.published >= start_date)
        if before:
            end_date = str_or_datetime_to_datetime(before)
            query = query.where(EyeballvulItem.published < end_date)

        return list(session.exec(query).all())


@typechecked
def get_by_project(
    repo_url: str,
    after: str | datetime | None = None,
    before: str | datetime | None = None,
) -> list[EyeballvulItem]:
    """
    Get the Eyeballvul items that match a project's repo URL.

    The list can be filtered with the optional `after` and `before` parameters, which must be ISO
    8601 dates.

    `after` is included, and `before` is excluded, i.e. the possible options are: (1) after <= date,
    (2) after <= date < before, (3) date < before.
    """
    engine = create_engine(f"sqlite:///{Config.paths.db}/eyeballvul.db")
    with Session(engine) as session:
        query = select(EyeballvulItem).where(EyeballvulItem.repo_url == repo_url)

        if after:
            start_date = str_or_datetime_to_datetime(after)
            query = query.where(EyeballvulItem.published >= start_date)
        if before:
            end_date = str_or_datetime_to_datetime(before)
            query = query.where(EyeballvulItem.published < end_date)

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

    `after` is included, and `before` is excluded, i.e. the possible options are: (1) after <= date,
    (2) after <= date < before, (3) date < before.

    The list can also be filtered by the `project` parameter, a repo URL.
    """
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

        results = session.exec(query).all()
        commits = {commit for item in results for commit in item.commits}
        return list(commits)


@typechecked
def get_revision(commit_hash: str) -> EyeballvulRevision | None:
    """Get the Eyeballvul revision that matches a commit hash."""
    if len(commit_hash) != 40:
        raise ValueError("The commit hash must be 40 characters long.")
    engine = create_engine(f"sqlite:///{Config.paths.db}/eyeballvul.db")
    with Session(engine) as session:
        query = select(EyeballvulRevision).where(EyeballvulRevision.commit == commit_hash)
        return session.exec(query).first()


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
def json_import(db_dest: Path = Config.paths.db) -> None:
    """Import the contents of the JSON files in the data directory into the SQL database at
    `db_dest`."""
    if db_dest.exists():
        raise ValueError(
            f"The database directory already exists at {db_dest}.\n"
            "Please remove it or back it up before importing."
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
