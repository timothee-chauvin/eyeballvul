import tomllib
from pathlib import Path
from typing import NamedTuple

PARENT_DIR = Path(__file__).parent
PROJECT_DIR = PARENT_DIR.parent.parent

with open(PARENT_DIR / "config.toml", "rb") as f:
    config = tomllib.load(f)


class Paths(NamedTuple):
    project: Path
    osv: Path
    data: Path
    repovul_vulns: Path
    repovul_revisions: Path
    db: Path
    repo_info_cache: Path
    repo_cache: Path
    workdir: Path


class Config:
    ecosystems = config["ecosystems"]
    supported_domains = config["supported_domains"]
    cache_path = Path(config["cache_path"]).expanduser()
    data_path = PROJECT_DIR / "data"

    paths = Paths(
        project=PROJECT_DIR,
        osv=cache_path / "osv",
        data=data_path,
        repovul_vulns=data_path / "vulns",
        repovul_revisions=data_path / "revisions",
        db=PROJECT_DIR / "db",
        repo_info_cache=cache_path / "repo_info",
        repo_cache=cache_path / "repos",
        workdir=Path(config["workdir"]),
    )


no_mkdir = [
    Config.paths.data,
    Config.paths.repovul_vulns,
    Config.paths.repovul_revisions,
    Config.paths.db,
]

# Create all directories in the config if they don't exist
for path in Config.paths:
    if path not in no_mkdir:
        path.mkdir(parents=True, exist_ok=True)
