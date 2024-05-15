class NoOsvItemsLeftError(Exception):
    """When all the OSV items for this repository have been filtered out (e.g. because they were
    withdrawn, or aren't using the "affected versions" syntax)."""


class RepoNotFoundError(Exception):
    """
    Git repository couldn't be cloned.

    Identified by "remote: Repository not found" in stderr of the process.
    """


class ConflictingCommitError(Exception):
    """When a repository has at least one commit that also exists at another repository URL (for
    instance when a repo has been renamed, or has forks)."""


class GitRuntimeError(Exception):
    """Error when running git commands."""


class LinguistError(Exception):
    """Error when running github-linguist."""
