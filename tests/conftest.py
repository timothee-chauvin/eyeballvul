from pathlib import Path

import pytest

PARENT_DIR = Path(__file__).parent


@pytest.fixture(scope="session")
def assets_dir() -> str:
    return str(PARENT_DIR / "assets")
