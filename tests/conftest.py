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
