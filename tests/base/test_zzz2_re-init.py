"""
This test is intended to be executed as last, just after the destroy test
(this is why it is prefixed as zzz2)
Beware: if env TEST_DESTROY_MODE == 1 this test will destroy your database, be careful
"""

import os

import pytest

from restapi.connectors import Connector
from restapi.server import ServerModes, create_app
from restapi.services.authentication import BaseAuthentication


# Only executed if tests are run with --destroy flag
@pytest.mark.skipif(
    not Connector.check_availability("authentication")
    or os.getenv("TEST_DESTROY_MODE", "0") != "1",
    reason="This test needs authentication and TEST_DESTROY_MODE to be enabled",
)
def test_init() -> None:
    if Connector.check_availability("sqlalchemy"):
        # Prevents errors like:
        # sqlalchemy.exc.ResourceClosedError: This Connection is closed
        Connector.disconnect_all()

    try:
        create_app(name="Flask Tests", mode=ServerModes.INIT, options={})
        # This is only a rough retry to prevent random errors from sqlalchemy
    except Exception:  # pragma: no cover
        create_app(name="Flask Tests", mode=ServerModes.INIT, options={})

    auth = Connector.get_authentication_instance()
    try:
        user = auth.get_user(username=BaseAuthentication.default_user)
    # SqlAlchemy sometimes can raise an:
    # AttributeError: 'NoneType' object has no attribute 'twophase'
    # due to the multiple app created... should be an issue specific of this test
    # In that case... simply retry.
    except AttributeError:  # pragma: no cover
        user = auth.get_user(username=BaseAuthentication.default_user)

    assert user is not None
