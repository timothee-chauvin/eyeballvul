import cProfile
import io
import json
import logging
import pstats
import time
import zipfile

import fire
import requests
from sqlmodel import Session, SQLModel, create_engine
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
    filtered_out = set()
    for item in items:
        repo_url = OSVVulnerability(**item).get_repo_url()
        if get_domain(repo_url) not in Config.supported_domains:
            filtered_out.add(repo_url)
            continue
        items_by_repo.setdefault(repo_url, []).append(item)
    logging.info(
        f"Kept {len(items_by_repo)} repos. {len(filtered_out)} unsupported repos filtered out."
    )
    return items_by_repo


@typechecked
def convert_one(repo_url: str, items: list[dict]) -> None:
    """Convert the OSV items of a single repository to Repovul items."""
    osv_items = [OSVVulnerability(**item) for item in items]
    repovul_items, repovul_revisions = osv_group_to_repovul_group(osv_items)
    engine = create_engine(f"sqlite:///{Config.paths.db}/repovul.db", echo=True)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        for repovul_item in repovul_items:
            session.merge(repovul_item)
        for repovul_revision in repovul_revisions:
            session.merge(repovul_revision)
        session.commit()


@typechecked
def convert_one_toplevel(repo_url: str) -> None:
    """Convert the OSV items of a single repository to Repovul items."""
    items = get_osv_items()
    by_repo = osv_items_by_repo(items)
    convert_one(repo_url, by_repo[repo_url])


@typechecked
def convert_all() -> None:
    """Convert the OSV items of all repositories to Repovul items."""
    items = get_osv_items()
    by_repo = osv_items_by_repo(items)
    start = time.time()
    for i, repo_url in enumerate(by_repo.keys()):
        logging.info(f"Processing {repo_url}...")
        convert_one(repo_url, by_repo[repo_url])
        elapsed = time.time() - start
        ETA = elapsed / (i + 1) * (len(by_repo) - i - 1)
        logging.info(f"({i+1}/{len(by_repo)}) elapsed {elapsed:.2f}s ETA {ETA:.2f}")


def main():
    fire.Fire(
        {
            "download": download,
            "convert_one": convert_one_toplevel,
            "convert_all": convert_all,
        }
    )


def profile():
    pr = cProfile.Profile()
    pr.enable()
    try:
        main()
    finally:
        pr.disable()
        pr.dump_stats("profile.stats")

        p = pstats.Stats("profile.stats")
        p.sort_stats("cumtime").print_stats(50)


if __name__ == "__main__":
    main()
