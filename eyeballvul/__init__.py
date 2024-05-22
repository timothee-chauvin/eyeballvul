from eyeballvul.api import (
    get_by_commit,
    get_by_project,
    get_commits,
    get_projects,
    get_revision,
    json_export,
    json_import,
)
from eyeballvul.config.config_loader import Config
from eyeballvul.models.eyeballvul import EyeballvulItem, EyeballvulRevision
from eyeballvul.score import score


def initialize_database():
    """Import the JSON-serialized data into the SQL database if it doesn't exist."""
    if not Config.paths.db.exists():
        print(f"Database doesn't exist at {Config.paths.db}. Initializing it from JSON data now.")
        print("This will only be done once, and may take a while...")
        json_import()


initialize_database()
