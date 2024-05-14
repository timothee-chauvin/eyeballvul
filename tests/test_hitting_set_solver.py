from datetime import datetime

from eyeballvul.util import solve_hitting_set


def test_solve_hitting_set():
    # fmt: off
    test_lists = [
        ["1", "2",      "4"],
        ["1", "2", "3"],
        ["1",      "3", "4"],
    ]
    # fmt: on
    version_dates_str = {
        "1": "2021-01-01T00:00:00",
        "2": "2021-01-02T00:00:00",
        "3": "2021-01-03T00:00:00",
        "4": "2021-01-04T00:00:00",
    }
    version_dates = {k: datetime.fromisoformat(v).timestamp() for k, v in version_dates_str.items()}
    assert solve_hitting_set(test_lists, version_dates) == ["1"]
