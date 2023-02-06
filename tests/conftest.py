import pytest
from faker import Faker
from flask import Flask

from restapi.server import ServerModes, create_app
from restapi.tests import BaseTests


@pytest.fixture
def app() -> Flask:
    return create_app(name="Flask Tests", mode=ServerModes.NORMAL, options={})


# Beware, this replaces the standard faker fixture provided by Faker it-self
@pytest.fixture
def faker() -> Faker:
    return BaseTests.faker
