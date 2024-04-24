import tomllib
from pathlib import Path

PARENT_DIR = Path(__file__).parent

with open(PARENT_DIR / "config.toml", "rb") as f:
    config = tomllib.load(f)


class Config:
    ecosystems = config["ecosystems"]
    base_path = Path(config["data_path"]).expanduser()

    paths = {
        "osv": base_path / "data/osv",
    }


# Create all directories in the config if they don't exist
for path in Config.paths.values():
    path.mkdir(parents=True, exist_ok=True)
