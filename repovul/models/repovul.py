from datetime import datetime
from pathlib import Path

from sqlmodel import JSON, Column, Field, SQLModel

from repovul.config.config_loader import Config
from repovul.models.common import Severity
from repovul.util import repo_url_to_name


class RepovulRevision(SQLModel, table=True):
    # Full commit hash
    commit: str = Field(primary_key=True)
    # Date of the commit. To be serialized as an ISO 8601 string,
    # e.g. "2021-09-01T00:00:00Z"
    date: datetime
    # Size in bytes of each programming language in the repo
    # at that commit, according to github linguist
    languages: dict[str, int] = Field(sa_column=Column(JSON))
    # Sum of all programming language sizes in bytes
    size: int

    class Config:
        validate_assignment = True

    def log(self) -> None:
        repovul_dir = Config.paths.repovul_revisions
        with open(repovul_dir / f"{self.commit}.json", "w") as f:
            f.write(self.model_dump_json(indent=2))
            f.write("\n")

    @staticmethod
    def from_file(filepath: str | Path) -> "RepovulRevision":
        with open(filepath) as f:
            return RepovulRevision.model_validate_json(f.read())


class RepovulItem(SQLModel, table=True):
    # Same as in osv.dev.
    # Get it from there at https://api.osv.dev/v1/vulns/{id}
    id: str = Field(primary_key=True)
    # Same as in osv.dev.
    published: datetime
    # Same as in osv.dev.
    modified: datetime
    # Same as in osv.dev.
    details: str
    # Same as in osv.dev.
    summary: str | None = None
    # Same as in asv.dev.
    severity: list[Severity] | None = Field(sa_column=Column(JSON))
    # Extracted from osv.dev.
    repo_url: str
    cwes: list[str] = Field(sa_column=Column(JSON))
    # Inferred from osv.dev and visiting the repo.
    # This maps to a list of RepovulRevision objects.
    commits: list[str] = Field(sa_column=Column(JSON))

    class Config:
        validate_assignment = True

    def log(self) -> None:
        repo_name = repo_url_to_name(self.repo_url)
        repovul_dir = Config.paths.repovul_vulns / repo_name
        repovul_dir.mkdir(parents=True, exist_ok=True)
        with open(repovul_dir / f"{self.id}.json", "w") as f:
            f.write(self.model_dump_json(indent=2, exclude_none=True))
            f.write("\n")

    @staticmethod
    def from_file(filepath: str | Path) -> "RepovulItem":
        with open(filepath) as f:
            return RepovulItem.model_validate_json(f.read())

    def to_dict(self) -> dict:
        return self.model_dump(exclude_none=True, mode="json")
