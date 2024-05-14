import re
from enum import Enum
from typing import Any

from pydantic import BaseModel

from eyeballvul.models.common import Severity


class OSVRangeType(str, Enum):
    UNSPECIFIED = "UNSPECIFIED"
    GIT = "GIT"
    SEMVER = "SEMVER"
    ECOSYSTEM = "ECOSYSTEM"


class OSVEvent(BaseModel):
    introduced: str | None = None
    fixed: str | None = None
    limit: str | None = None
    last_affected: str | None = None


class OSVRange(BaseModel):
    type: OSVRangeType = OSVRangeType.UNSPECIFIED
    repo: str | None = None
    events: list[OSVEvent]


class OSVPackage(BaseModel):
    name: str
    ecosystem: str
    purl: str | None = None


class OSVAffected(BaseModel):
    ranges: list[OSVRange] | None = None
    package: OSVPackage | None = None
    versions: list[str] | None = None
    ecosystem_specific: dict | None = None
    database_specific: dict | None = None
    severity: list[Severity] | None = None


class OSVReferenceType(str, Enum):
    NONE = "NONE"
    WEB = "WEB"
    ADVISORY = "ADVISORY"
    REPORT = "REPORT"
    FIX = "FIX"
    PACKAGE = "PACKAGE"
    ARTICLE = "ARTICLE"
    EVIDENCE = "EVIDENCE"


class OSVReference(BaseModel):
    type: OSVReferenceType = OSVReferenceType.NONE
    url: str


class OSVVulnerability(BaseModel):
    id: str
    published: str
    modified: str
    details: str
    affected: list[OSVAffected]
    summary: str | None = None
    withdrawn: str | None = None
    aliases: list[str] | None = None
    related: list[str] | None = None
    references: list[OSVReference] | None = None
    severity: list[Severity] | None = None
    database_specific: Any | None = None

    def get_repo_url(self) -> str:
        """Return the lowercase repo URL."""
        for affected in self.affected:
            if affected.ranges:
                for range_ in affected.ranges:
                    if range_.type == OSVRangeType.GIT and range_.repo:
                        # TODO not exactly correct, sometimes there are two repo urls for the same item,
                        # e.g. CVE-2017-6908
                        return range_.repo.lower()
        raise ValueError(f"No repo URL found for item {self.id}")

    def get_affected_versions(self) -> list[str] | None:
        for affected in self.affected:
            if affected.versions:
                return affected.versions
        return None

    def get_last_affected(self) -> str | None:
        for affected in self.affected:
            if affected.ranges:
                for range_ in affected.ranges:
                    for event in range_.events:
                        if event.last_affected:
                            return event.last_affected
        return None

    def get_fixed(self) -> str | None:
        for affected in self.affected:
            if affected.ranges:
                for range_ in affected.ranges:
                    for event in range_.events:
                        if event.fixed:
                            return event.fixed
        return None

    def get_cwes(self) -> list[str]:
        """Try finding CWEs from a few possible places."""
        cwe_regex = r"^CWE-\d+$"
        cwe_url_regex = r"https://cwe.mitre.org/data/definitions/(\d+).html"
        cwes = []
        # Try finding in databaseSpecific["CWE"]["id"]
        if (
            self.database_specific is not None
            and "CWE" in self.database_specific
            and "id" in self.database_specific["CWE"]
        ):
            cwe_id = self.database_specific["CWE"]["id"]
            match = re.match(cwe_regex, cwe_id)
            if match:
                cwes.append(match.group())
        # Try finding in references with type=="WEB" and url=="https://cwe.mitre.org/data/definitions/<cwe_number>.html"
        for reference in self.references or []:
            if reference.type == OSVReferenceType.WEB:
                match = re.match(cwe_url_regex, reference.url)
                if match:
                    cwes.append(f"CWE-{match.group(1)}")
        return sorted(cwes)
