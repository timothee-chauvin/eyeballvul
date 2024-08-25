class UnsupportedDomainError(Exception):
    """When the domain of the project URL is not in Config.supported_domains."""


class AllOsvItemsWithdrawnError(Exception):
    """When all the OSV items for this repository have been withdrawn."""


class NoAffectedVersionsError(Exception):
    """
    When at least one non-withdrawn OSV item in the repository doesn't use the "affected versions"
    syntax.

    The whole repository is skipped to avoid potential true positives being marked as false
    positives.
    """


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
