class RepoNotFoundError(Exception):
    """
    Git repository couldn't be cloned.

    Identified by "remote: Repository not found" in stderr of the process.
    """


class GitRuntimeError(Exception):
    """Error when running git commands."""


class LinguistError(Exception):
    """Error when running github-linguist."""
