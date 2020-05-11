import os
import pytest
from restapi.server import create_app


@pytest.fixture
def app():
    os.environ['TESTING'] = "1"
    app = create_app(testing_mode=True)
    return app
