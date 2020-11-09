import os

from restapi.connectors import sqlalchemy
from restapi.exceptions import ServiceUnavailable
from restapi.server import ServerModes, create_app
from restapi.services.authentication import BaseAuthentication
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_destroy():

    # Only executed if tests are run with --destroy flag
    if os.getenv("TEST_DESTROY_MODE", "0") != "1":
        log.info("Skipping destroy test, TEST_DESTROY_MODE not enabled")
        return False

    if not detector.check_availability("authentication"):
        log.warning("Skipping authentication test: service not available")
        return False

    if detector.check_availability("sqlalchemy"):
        sql = sqlalchemy.get_instance()
        # Close previous connections, otherwise the new create_app will hang
        sql.session.remove()
        sql.session.close_all()

    auth = detector.get_authentication_instance()

    user = auth.get_user(username=BaseAuthentication.default_user)
    assert user is not None

    create_app(mode=ServerModes.DESTROY)

    try:
        user = auth.get_user(username=BaseAuthentication.default_user)
        assert user is None
    except ServiceUnavailable:
        pass

    create_app(mode=ServerModes.INIT)

    user = auth.get_user(username=BaseAuthentication.default_user)
    assert user is not None
