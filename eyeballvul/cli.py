import cProfile
import io
import logging
import pstats
import sys
import zipfile

import fire
import requests

from eyeballvul.api import json_export, json_import
from eyeballvul.config.config_loader import Config
from eyeballvul.converter import Converter

logging.basicConfig(
    level=logging.INFO, format="%(levelname)s-%(process)d-%(asctime)s - %(message)s"
)


def fatal(message: str) -> None:
    """Print a message to stderr and exit with status 1."""
    print(message, file=sys.stderr)
    sys.exit(1)


class Build:
    """The group of functions used in building the eyeballvul dataset from osv.dev."""

    @staticmethod
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

    @staticmethod
    def convert_one(repo_url: str) -> None:
        return Converter().convert_one(repo_url)

    @staticmethod
    def convert_all() -> None:
        return Converter().convert_all()

    @staticmethod
    def convert_range(start: int, end: int) -> None:
        return Converter().convert_range(start, end)

    @staticmethod
    def postprocess() -> None:
        return Converter().postprocess()


def json_import_cli() -> None:
    """Import the contents of the JSON files in the data directory into the SQL database."""
    json_import()


def json_export_cli() -> None:
    """Export the contents of the SQL database into JSON files in the data directory."""
    json_export()


def main():
    fire.Fire(
        {
            "build": Build,
            "json_export": json_export_cli,
            "json_import": json_import_cli,
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
