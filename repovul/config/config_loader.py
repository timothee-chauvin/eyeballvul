import tomllib
from pathlib import Path
from typing import NamedTuple

PARENT_DIR = Path(__file__).parent

with open(PARENT_DIR / "config.toml", "rb") as f:
    config = tomllib.load(f)


class Paths(NamedTuple):
    project: Path
    osv: Path
    repo_cache: Path
    workdir: Path


class Config:
    ecosystems = config["ecosystems"]
    supported_domains = config["supported_domains"]
    base_path = Path(config["data_path"]).expanduser()

    paths = Paths(
        project=PARENT_DIR.parent.parent,
        osv=base_path / "data/osv",
        repo_cache=base_path / "repo_cache",
        workdir=Path(config["workdir"]),
    )


# Create all directories in the config if they don't exist
for path in Config.paths:
    path.mkdir(parents=True, exist_ok=True)
