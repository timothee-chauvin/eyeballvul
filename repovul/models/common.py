from enum import Enum

from pydantic import BaseModel


class SeverityType(str, Enum):
    UNSPECIFIED = "UNSPECIFIED"
    CVSS_V3 = "CVSS_V3"
    CVSS_V2 = "CVSS_V2"


class Severity(BaseModel):
    type: SeverityType
    score: str
