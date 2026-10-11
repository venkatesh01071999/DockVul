"""Shared fixtures for all component tests. Component-specific fixtures live in tests/<component>/conftest.py."""
import pytest


@pytest.fixture(autouse=True)
def _mark_unit(request):
    """Tag every test that isn't explicitly `integration` as `unit`, so `pytest -m unit` works."""
    if request.node.get_closest_marker("integration") is None:
        request.node.add_marker(pytest.mark.unit)
