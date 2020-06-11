import pytest

from restapi.server import create_app
from restapi.services.mailmock import SMTP
from restapi.tests import get_faker


@pytest.fixture
def app(mocker):

    mocker.patch("smtplib.SMTP", return_value=SMTP)
    mocker.patch("smtplib.SMTP_SSL", return_value=SMTP)
    app = create_app(testing_mode=True)
    return app


@pytest.fixture
def fake():
    return get_faker()
