import os
import pytest

from restapi.server import create_app
from restapi.tests import get_faker


@pytest.fixture
def app():
    app = create_app(testing_mode=True)
    return app


@pytest.fixture
def fake():
    return get_faker()


def pytest_sessionfinish(session, exitstatus):
    if os.getenv("TEST_DESTROY_MODE", '0') == '1':
        create_app(destroy_mode=True)
