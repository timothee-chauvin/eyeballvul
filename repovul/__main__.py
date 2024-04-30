import io
import json
import logging
import zipfile

import fire
import requests
from typeguard import typechecked

from repovul.config import Config
from repovul.models.osv import OSVVulnerability
from repovul.models.repovul import osv_group_to_repovul_group
from repovul.util import get_domain

logging.basicConfig(level=logging.INFO)


def download():
    """Download and extract the data from the osv.dev dataset."""
    ecosystems = Config.ecosystems
    url_template = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
    for ecosystem in ecosystems:
        destination = Config.paths.osv / ecosystem
        url = url_template.format(ecosystem=ecosystem)
        logging.info(f"Downloading data from {ecosystem}...")
        response = requests.get(url, timeout=30)
        z = zipfile.ZipFile(io.BytesIO(response.content))
        z.extractall(destination)


@typechecked
def get_osv_items() -> list[dict]:
    """Get the items from the osv.dev dataset."""
    osv_path = Config.paths.osv
    items = []
    for ecosystem in Config.paths.osv.iterdir():
        for item_basename in ecosystem.iterdir():
            with open(osv_path / ecosystem / item_basename) as f:
                item = json.load(f)
            items.append(item)
    return items


@typechecked
def osv_items_by_repo(items: list[dict]) -> dict[str, list]:
    """
    Group the items from the osv.dev dataset by repository.

    Filtering out unsupported domains is done in this function.
    """
    items_by_repo: dict[str, list] = {}
    for item in items:
        repo_url = OSVVulnerability(**item).get_repo_url()
        if get_domain(repo_url) not in Config.supported_domains:
            continue
        items_by_repo.setdefault(repo_url, []).append(item)
    return items_by_repo


@typechecked
def convert_one(repo_url: str) -> None:
    """Convert the OSV items of a single repository to Repovul items."""
    items = get_osv_items()
    by_repo = osv_items_by_repo(items)
    osv_items = [OSVVulnerability(**item) for item in by_repo[repo_url]]
    repovul_items = osv_group_to_repovul_group(osv_items)
    for repovul_item in repovul_items:
        repovul_item.log()


def main():
    fire.Fire({"download": download, "convert_one": convert_one})


if __name__ == "__main__":
    main()
