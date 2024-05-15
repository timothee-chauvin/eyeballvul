import json
from collections.abc import ItemsView, KeysView, ValuesView

from pydantic import BaseModel, RootModel

from eyeballvul.config.config_loader import Config


class CacheItem(BaseModel):
    versions_info: dict[str, tuple[str, float] | None]
    hitting_set_results: dict[str, list[str]]
    doesnt_exist: bool | None = None
    conflicts_with: str | None = None

    def __eq__(self, other):
        if isinstance(other, CacheItem):
            return (
                self.compare_versions_info(other.versions_info)
                and self.compare_hitting_set_results(other.hitting_set_results)
                and self.doesnt_exist == other.doesnt_exist
                and self.conflicts_with == other.conflicts_with
            )
        return False

    def compare_versions_info(self, other_versions_info):
        if self.versions_info.keys() != other_versions_info.keys():
            return False
        return all(
            self.versions_info[key] == other_versions_info[key] for key in self.versions_info
        )

    def compare_hitting_set_results(self, other_hitting_set_results):
        if self.hitting_set_results.keys() != other_hitting_set_results.keys():
            return False
        return all(
            set(self.hitting_set_results[key]) == set(other_hitting_set_results[key])
            for key in self.hitting_set_results
        )


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
        """Write the cache to the cache file, ensuring the file won't be lost if this function is
        interrupted in the middle."""
        tmp_cache_filepath = Config.paths.repo_info_cache / "cache.tmp.json"
        cache_filepath = Config.paths.repo_info_cache / "cache.json"
        with open(tmp_cache_filepath, "w") as f:
            f.write(self.model_dump_json(indent=2, exclude_unset=True))
            f.write("\n")
        tmp_cache_filepath.replace(cache_filepath)

    def initialize(self, repo_url: str) -> None:
        if repo_url not in self:
            self[repo_url] = CacheItem(
                versions_info={},
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

    def __len__(self) -> int:
        return len(self.root)

    def keys(self) -> KeysView[str]:
        return self.root.keys()

    def values(self) -> ValuesView[CacheItem]:
        return self.root.values()

    def items(self) -> ItemsView[str, CacheItem]:
        return self.root.items()

    def get(self, key: str, default: CacheItem | None = None) -> CacheItem | None:
        return self.root.get(key, default)
