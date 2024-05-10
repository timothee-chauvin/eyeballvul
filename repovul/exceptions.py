class RepoNotFoundError(Exception):
    """
    Git repository couldn't be cloned.

    Identified by "remote: Repository not found" in stderr of the process.
    """
