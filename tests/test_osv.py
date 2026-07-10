import json
from pathlib import Path

import pytest

from eyeballvul.models.osv import OSVVulnerability


@pytest.mark.parametrize(
    "osv_id, expected",
    [
        ("CURL-CVE-2000-0973", {"CWE-121"}),
        ("CVE-2023-33747", {"CWE-35", "CWE-264", "CWE-269"}),
    ],
)
def test_get_cwes(assets_dir, osv_id, expected):
    with open(Path(assets_dir) / "osv_items" / f"{osv_id}.json") as f:
        osv_item_json = json.load(f)
    item = OSVVulnerability(**osv_item_json)
    assert set(item.get_cwes()) == expected


def test_get_details(assets_dir):
    # Some upstream items (e.g. Oracle-CNA ones re-exported by osv.dev on 2026-07-08)
    # have no details. get_details() falls back to the summary.
    with open(Path(assets_dir) / "osv_items" / "CURL-CVE-2000-0973.json") as f:
        osv_item_json = json.load(f)
    assert OSVVulnerability(**osv_item_json).get_details() == osv_item_json["details"]
    del osv_item_json["details"]
    item = OSVVulnerability(**osv_item_json)
    assert item.details is None
    assert item.get_details() == osv_item_json["summary"]
    del osv_item_json["summary"]
    with pytest.raises(ValueError):
        OSVVulnerability(**osv_item_json).get_details()
