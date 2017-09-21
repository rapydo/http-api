import pytest
import os
from restapi.server import create_app

__author__ = "Mattia D'Antonio (m.dantonio@cineca.it)"


@pytest.fixture
def app():
    os.environ["TESTING_FLASK"]=True
    app = create_app()
    return app
