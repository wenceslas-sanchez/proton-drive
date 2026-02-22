import os

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list) -> None:
    missing = not (os.getenv("PROTON_TEST_USERNAME") and os.getenv("PROTON_TEST_PASSWORD"))
    if not missing:
        return
    mark_expr = getattr(config.option, "markexpr", "")
    if "integration" in mark_expr:
        return
    skip = pytest.mark.skip(reason="PROTON_TEST_USERNAME / PROTON_TEST_PASSWORD not set")
    for item in items:
        if item.get_closest_marker("integration"):
            item.add_marker(skip)


@pytest.fixture(scope="session")
def proton_credentials() -> tuple[str, str]:
    username = os.getenv("PROTON_TEST_USERNAME")
    password = os.getenv("PROTON_TEST_PASSWORD")
    if not username or not password:
        pytest.fail(
            "PROTON_TEST_USERNAME and PROTON_TEST_PASSWORD must be set to run integration tests."
        )
    return username, password
