# Changelog
`eyeballvul` adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), and this file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]
### Changed
- \[build\] building the benchmark now terminates with a non-zero exit status in case of any git runtime error.
- \[build\] all repositories for which at least one item doesn't have an "affected versions" field are dropped, to avoid true positives being potentially marked as false positives. This concerned 326 repositories out of 6,025 in the benchmark, or 5.4\% of repositories.
- \[build\] in the statistics after building the benchmark, the number of repositories for which no versions were found by git is now reported.
- \[build\] the number of repositories ignored because their domain isn't supported is now reported in the statistics.

## [0.7.0] - 2024-07-08
### Changed
- the LLM scorer now uses YAML, few-shot prompting, Claude 3.5 Sonnet at temperature 0, and asks for a reasoning step before giving the response.
- `Stats` and `StatsWithCutoff` are no longer dataclasses.
- `get_vulns`, `get_commits` and `get_revisions` now only accept keyword arguments.

### Added
- an async version of `compute_score` has been added, named `acompute_score`.
- an `id` argument has been added to `get_vulns`, to filter by CVE ID.
- up to 5 retries are now automatically tried by the LLM scorer, in case of API errors or incorrect YAML.

## [0.6.1] - 2024-06-08
### Fixed
- fixed incorrect initialization of EyeballvulScore in compute_score()

## [0.6.0] - 2024-06-08
### Changed
- `EyeballvulScore`, `Stats`, and `StatsWithCutoff` are now Pydantic models. The schema of `EyeballvulScore` has changed. To get the stats of an `EyeballvulScore`, either the `stats` attributes should be directly accessed, or the `stats_with_cutoff` method should be used in case of a cutoff date.

## [0.5.1] - 2024-06-06
### Added
- It is now possible to run `from eyeballvul import EyeballvulScore` instead of `from eyeballvul.score import EyeballvulScore`.

### Fixed
- fixed bug where an error was raised when `stats.fp` was 0 when initializing `EyeballvulScore`

## [0.5.0] - 2024-06-06
### Changed
- `score` has been renamed to `compute_score`. It now returns an `EyeballvulScore` object instead of the previous `tuple[dict[str, int] | dict[str, int | dict[str, int]], dict[int, str]]`. The `cutoff_date` has been removed, this can now be done after the fact by calling `EyeballvulScore.stats(cutoff_date: datetime | None = None)`.

## [0.4.1] - 2024-05-28
### Added
- `get_revisions` has been added to the API.

## [0.4.0] - 2024-05-27
### Added
- a new function has been added to the API: `get_vulns(after, before, project, commit)`.

### Changed
- `get_by_project` has been removed from the API. Use `get_vulns(project=project)` instead.
- `get_by_commit` has been removed from the API. Use `get_vulns(commit=commit)` instead.
- for consistency, the unique parameter of `get_revision` has been renamed from `commit_hash` to `commit`.
- `get_revision` now either returns an `EyeballvulRevision`, or raises a `ValueError`, instead of returning `EyeballvulRevision | None`.

## [0.3.0] - 2024-05-24
### Changed
- the JSON data and associated SQLite database now live in `~/.cache/eyeballvul` by default, and a function to download data has been added to the API.

## [0.2.0] - 2024-05-22
### Added
- dates can be supplied as either `str` or `datetime` in the python API.

### Changed
- the minimum supported Python version has been lowered to 3.10 (from 3.11).
- initializing the database from the JSON data is now done automatically the first time the package is imported.

## [0.1.0] - 2024-05-18
Initial release.
