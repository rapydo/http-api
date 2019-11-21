import pytest
from restapi.server import create_app


@pytest.fixture
def app():
    app = create_app(testing_mode=True)
    return app
