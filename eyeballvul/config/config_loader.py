from pathlib import Path
from typing import NamedTuple

import tomli

PARENT_DIR = Path(__file__).parent
PROJECT_DIR = PARENT_DIR.parent.parent

with open(PARENT_DIR / "config.toml", "rb") as f:
    config = tomli.load(f)


class Paths(NamedTuple):
    project: Path
    osv: Path
    data: Path
    eyeballvul_vulns: Path
    eyeballvul_revisions: Path
    db: Path
    repo_info_cache: Path
    workdir: Path


class Config:
    ecosystems = config["ecosystems"]
    supported_domains = config["supported_domains"]
    cache_path = Path(config["cache_path"]).expanduser()
    data_path = cache_path / "data"
    scoring_model = config["scoring_model"]
    eyeballvul_data_api = "https://api.github.com/repos/timothee-chauvin/eyeballvul_data"

    paths = Paths(
        project=PROJECT_DIR,
        osv=cache_path / "osv",
        data=data_path,
        eyeballvul_vulns=data_path / "vulns",
        eyeballvul_revisions=data_path / "revisions",
        db=cache_path / "db",
        repo_info_cache=cache_path / "repo_info",
        workdir=Path(config["workdir"]),
    )


no_mkdir = [
    Config.paths.data,
    Config.paths.eyeballvul_vulns,
    Config.paths.eyeballvul_revisions,
    Config.paths.db,
]

# Create all directories in the config if they don't exist
for path in Config.paths:
    if path not in no_mkdir:
        path.mkdir(parents=True, exist_ok=True)
