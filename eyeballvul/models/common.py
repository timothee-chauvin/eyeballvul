from typing import Literal

from typing_extensions import TypedDict


class Severity(TypedDict):
    type: Literal["CVSS_V3", "CVSS_V2", "UNSPECIFIED"]
    score: str
