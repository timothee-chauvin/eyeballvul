import json

from pydantic import BaseModel, RootModel

from repovul.config.config_loader import Config


class CacheItem(BaseModel):
    versions_to_commits: dict[str, str]
    commits_to_dates: dict[str, str]
    hitting_set_results: dict[str, list[str]]


class Cache(RootModel):
    root: dict[str, CacheItem]

    @staticmethod
    def read() -> "Cache":
        """Read the cache from the cache file."""
        cache_filepath = Config.paths.repo_info_cache / "cache.json"
        if not cache_filepath.exists():
            return Cache({})
        else:
            with open(cache_filepath) as f:
                return Cache(json.load(f))

    def write(self) -> None:
        """Write the cache to the cache file."""
        cache_filepath = Config.paths.repo_info_cache / "cache.json"
        with open(cache_filepath, "w") as f:
            f.write(self.model_dump_json(indent=2))
            f.write("\n")

    def initialize(self, repo_url: str) -> None:
        if repo_url not in self:
            self[repo_url] = CacheItem(
                versions_to_commits={},
                commits_to_dates={},
                hitting_set_results={},
            )

    def __getitem__(self, key: str) -> CacheItem:
        return self.root[key]

    def __setitem__(self, key: str, value: CacheItem) -> None:
        self.root[key] = value

    def __delitem__(self, key: str) -> None:
        del self.root[key]

    def __contains__(self, key: str) -> bool:
        return key in self.root
