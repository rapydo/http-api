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

    auth = Connector.get_authentication_instance()
    if Connector.authentication_service == "sqlalchemy":
        # Re-init does not work with MySQL due to issues with previous connections
        # Considering that:
        # 1) this is a workaround to test the initialization
        #       (not the normal workflow used by the application)
        # 2) the init is already tested with any other DB, included postgres
        # 3) MySQL is not used by any project
        # => there is no need to go crazy in debugging this issue!
        if auth.db.is_mysql():  # type: ignore
            return

        # sql = sqlalchemy.get_instance()

    if Connector.check_availability("sqlalchemy"):
        # Prevents errors like:
        # sqlalchemy.exc.ResourceClosedError: This Connection is closed
        Connector.disconnect_all()

        # sql = sqlalchemy.get_instance()
        # # Close previous connections, otherwise the new create_app will hang
        # sql.session.remove()
        # sql.session.close_all()

    try:
        create_app(mode=ServerModes.INIT)
        # This is only a rough retry to prevent random errors from sqlalchemy
    except Exception:  # pragma: no cover
        create_app(mode=ServerModes.INIT)

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
