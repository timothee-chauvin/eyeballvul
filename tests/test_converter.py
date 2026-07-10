import json
from pathlib import Path

from eyeballvul.converter import Converter


def test_osv_items_by_repo_drops_items_without_description(assets_dir):
    with open(Path(assets_dir) / "osv_items" / "CVE-2023-33747.json") as f:
        item = json.load(f)
    no_description = {k: v for k, v in item.items() if k not in ("details", "summary")}
    no_description["id"] = "CVE-TEST-NO-DESCRIPTION"

    by_repo = Converter.osv_items_by_repo([item, no_description])

    ids = [i["id"] for group in by_repo.values() for i in group]
    assert ids == [item["id"]]
