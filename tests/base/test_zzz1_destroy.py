"""
This test is intended to be executed as second-last, just before the re-init test
(this is why it is prefixed as zzz1)
Beware: if env TEST_DESTROY_MODE == 1 this test will destroy your database, be careful
"""

import os

import pytest

from restapi.connectors import Connector
from restapi.exceptions import ServiceUnavailable
from restapi.server import ServerModes, create_app
from restapi.services.authentication import BaseAuthentication


# Only executed if tests are run with --destroy flag
@pytest.mark.skipif(
    not Connector.check_availability("authentication")
    or os.getenv("TEST_DESTROY_MODE", "0") != "1",
    reason="This test needs authentication and TEST_DESTROY_MODE to be enabled",
)
def test_destroy() -> None:
    auth = Connector.get_authentication_instance()

    user = auth.get_user(username=BaseAuthentication.default_user)
    assert user is not None

    create_app(name="Flask Tests", mode=ServerModes.DESTROY, options={})

    if Connector.check_availability("sqlalchemy"):
        with pytest.raises(ServiceUnavailable):
            auth = Connector.get_authentication_instance()
            user = auth.get_user(username=BaseAuthentication.default_user)
    else:
        auth = Connector.get_authentication_instance()
        user = auth.get_user(username=BaseAuthentication.default_user)
        assert user is None
