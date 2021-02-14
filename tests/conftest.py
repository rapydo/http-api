import pytest

from restapi.server import create_app
from restapi.tests import BaseTests


@pytest.fixture
def app():
    return create_app()


# Beware, this replaces the standard faker fixture provided by Faker it-self
@pytest.fixture
def faker():

    return BaseTests.faker
