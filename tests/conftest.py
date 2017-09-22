import pytest
from restapi.server import create_app

__author__ = "Mattia D'Antonio (m.dantonio@cineca.it)"


@pytest.fixture
def app():
    app = create_app(testing_mode=True)
    return app
