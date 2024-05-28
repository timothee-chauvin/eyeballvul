# Changelog
`eyeballvul` adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), and this file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

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
