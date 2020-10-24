import pytest

from restapi.server import create_app
from restapi.tests import get_faker


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def fake():
    return get_faker()
