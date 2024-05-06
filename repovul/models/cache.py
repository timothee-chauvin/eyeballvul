import json

from pydantic import BaseModel

from repovul.config.config_loader import Config


class CacheItem(BaseModel):
    versions_to_commits: dict[str, str]
    commits_to_dates: dict[str, str]
    hitting_set_results: dict[str, list[str]]


class Cache(BaseModel):
    items: dict[str, CacheItem]

    @staticmethod
    def read() -> "Cache":
        """Read the cache from the cache file."""
        cache_filepath = Config.paths.repo_info_cache / "cache.json"
        if not cache_filepath.exists():
            return Cache(items={})
        else:
            with open(cache_filepath) as f:
                return Cache(**json.load(f))

    def write(self) -> None:
        """Write the cache to the cache file."""
        cache_filepath = Config.paths.repo_info_cache / "cache.json"
        with open(cache_filepath, "w") as f:
            f.write(self.model_dump_json(indent=2))
            f.write("\n")
