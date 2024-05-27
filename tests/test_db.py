import pytest
from sqlmodel import Session, create_engine, select

from eyeballvul.api import json_import
from eyeballvul.models.eyeballvul import EyeballvulItem, EyeballvulRevision


@pytest.fixture(scope="module")
def db_session(tmp_path_factory):
    tmpdir = tmp_path_factory.mktemp("data")
    db_path = tmpdir / "db"
    json_import(db_path)
    engine = create_engine(f"sqlite:///{db_path}/eyeballvul.db")
    with Session(engine) as session:
        yield session


def test_db_commit_to_revision_integrity(db_session):
    """Check that for each commit in each EyeballvulItem, the corresponding revision exists and has
    the same repo URL."""
    for item in db_session.exec(select(EyeballvulItem)).all():
        for commit in item.commits:
            revision = db_session.get(EyeballvulRevision, commit)
            assert revision is not None
            assert revision.repo_url == item.repo_url


def test_db_stale_revisions(db_session):
    """Check that there are no revisions without a corresponding EyeballvulItem."""
    revision_commits = {
        revision.commit for revision in db_session.exec(select(EyeballvulRevision)).all()
    }
    item_commits = {
        commit for item in db_session.exec(select(EyeballvulItem)).all() for commit in item.commits
    }
    assert revision_commits == item_commits


def test_no_empty_revisions(db_session):
    """Check that all revisions have a size at least equal to 1."""
    assert (
        db_session.exec(select(EyeballvulRevision).where(EyeballvulRevision.size == 0)).all() == []
    )


def test_no_empty_commit_list(db_session):
    """Check that all EyeballvulItems have at least one commit."""
    assert db_session.exec(select(EyeballvulItem).where(EyeballvulItem.commits == [])).all() == []
