import json
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlmodel import JSON, Column, Field, SQLModel, UniqueConstraint

from eyeballvul.config.config_loader import Config
from eyeballvul.models.common import Severity


class EyeballvulRevision(SQLModel, table=True):
    # Full commit hash
    commit: str = Field(primary_key=True)
    # Repository URL
    repo_url: str = Field(index=True)
    # Date of the commit. To be serialized as an ISO 8601 string,
    # e.g. "2021-09-01T00:00:00Z"
    date: datetime
    # Size in bytes of each programming language in the repo
    # at that commit, according to github linguist
    languages: dict[str, int] = Field(sa_column=Column(JSON))
    # Sum of all programming language sizes in bytes
    size: int

    __table_args__ = (UniqueConstraint("repo_url", "commit"),)

    class Config:
        validate_assignment = True

    def log(self) -> None:
        year = str(self.date.year)
        month = f"{self.date.month:02d}"
        dest_dir = Config.paths.eyeballvul_revisions / year / month
        dest_dir.mkdir(parents=True, exist_ok=True)
        with open(dest_dir / f"{self.commit}.json", "w") as f:
            json.dump(self.to_dict(), f, indent=2)
            f.write("\n")

    @staticmethod
    def from_file(filepath: str | Path) -> "EyeballvulRevision":
        with open(filepath) as f:
            return EyeballvulRevision.model_validate_json(f.read())

    def to_dict(self) -> dict[str, Any]:
        # We can't simply use self.model_dump() because we need
        # determinism in the key order, since the output is tracked by git.
        return {
            "commit": self.commit,
            "repo_url": self.repo_url,
            "date": self.date.isoformat(),
            "languages": self.languages,
            "size": self.size,
        }


class EyeballvulItem(SQLModel, table=True):
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
    repo_url: str = Field(index=True)
    cwes: list[str] = Field(sa_column=Column(JSON))
    # Inferred from osv.dev and visiting the repo.
    # This maps to a list of EyeballvulRevision objects.
    commits: list[str] = Field(sa_column=Column(JSON))

    class Config:
        validate_assignment = True

    def log(self) -> None:
        year = str(self.published.year)
        month = f"{self.published.month:02d}"
        dest_dir = Config.paths.eyeballvul_vulns / year / month
        dest_dir.mkdir(parents=True, exist_ok=True)
        with open(dest_dir / f"{self.id}.json", "w") as f:
            json.dump(self.to_dict(), f, indent=2)
            f.write("\n")

    @staticmethod
    def from_file(filepath: str | Path) -> "EyeballvulItem":
        with open(filepath) as f:
            return EyeballvulItem.model_validate_json(f.read())

    def to_dict(self) -> dict[str, Any]:
        # We can't simply use self.model_dump() because we need
        # determinism in the key order, since the output is tracked by git.
        dic: dict[str, Any] = {
            "id": self.id,
            "published": self.published.isoformat(),
            "modified": self.modified.isoformat(),
            "details": self.details,
        }
        if self.summary is not None:
            dic["summary"] = self.summary
        if self.severity is not None:
            dic["severity"] = self.severity
        dic.update(
            {
                "repo_url": self.repo_url,
                "cwes": sorted(self.cwes),
                "commits": sorted(self.commits),
            }
        )
        return dic
