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
