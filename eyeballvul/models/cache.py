import json
import logging
from collections.abc import ItemsView, KeysView, ValuesView
from pathlib import Path
from urllib.parse import urlparse

from pydantic import BaseModel, RootModel

from eyeballvul.config.config_loader import Config


def _repo_url_to_path(cache_dir: Path, repo_url: str) -> Path:
    parsed = urlparse(repo_url)
    repo_path = parsed.path.strip("/")
    return cache_dir / parsed.netloc / f"{repo_path}.json"


def _path_to_repo_url(cache_dir: Path, path: Path) -> str:
    rel = path.relative_to(cache_dir).with_suffix("")
    domain = rel.parts[0]
    rest = "/".join(rel.parts[1:])
    return f"https://{domain}/{rest}"


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
    def _cache_dir() -> Path:
        return Config.paths.repo_info_cache

    @staticmethod
    def read() -> "Cache":
        """Read the cache from per-repo JSON files, falling back to legacy single-file format."""
        cache_dir = Cache._cache_dir()
        legacy_path = cache_dir / "cache.json"
        if legacy_path.exists():
            logging.info("Reading legacy single-file cache...")
            with open(legacy_path) as f:
                cache = Cache(json.load(f))
            logging.info(f"Migrating {len(cache)} cache entries to per-repo files...")
            cache.write_all()
            legacy_path.unlink()
            logging.info("Migration complete. Deleted legacy cache.json.")
            return cache
        items: dict[str, CacheItem] = {}
        for json_file in cache_dir.rglob("*.json"):
            if json_file.name.endswith(".tmp.json"):
                continue
            repo_url = _path_to_repo_url(cache_dir, json_file)
            with open(json_file) as f:
                items[repo_url] = CacheItem(**json.load(f))
        return Cache(items)

    def write_one(self, repo_url: str) -> None:
        """Write a single repo's cache entry to its own file, atomically."""
        cache_dir = self._cache_dir()
        path = _repo_url_to_path(cache_dir, repo_url)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(".tmp.json")
        item = self.root[repo_url]
        with open(tmp_path, "w") as f:
            f.write(
                json.dumps(item.model_dump(mode="json", exclude_none=True), separators=(",", ":"))
            )
            f.write("\n")
        tmp_path.replace(path)

    def write_all(self) -> None:
        """Write all cache entries to per-repo files."""
        for repo_url in self.root:
            self.write_one(repo_url)

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
