from pathlib import Path

from sqlmodel import Session, create_engine, select

from eyeballvul.__main__ import json_import_to_dest
from eyeballvul.models.eyeballvul import EyeballvulItem, EyeballvulRevision


def test_db_integrity(tmpdir):
    """Check that for each commit in each EyeballvulItem, the corresponding revision exists and has
    the same repo URL."""
    db_path = Path(tmpdir) / "db"
    json_import_to_dest(db_path)
    engine = create_engine(f"sqlite:///{db_path}/eyeballvul.db")
    with Session(engine) as session:
        for item in session.exec(select(EyeballvulItem)).all():
            for commit in item.commits:
                revision = session.get(EyeballvulRevision, commit)
                assert revision is not None
                assert revision.repo_url == item.repo_url
