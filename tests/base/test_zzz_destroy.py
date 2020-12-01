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

    # Always enable during core tests
    if not detector.check_availability("authentication"):  # pragma: no cover
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
        auth = detector.get_authentication_instance()
        user = auth.get_user(username=BaseAuthentication.default_user)
        assert user is None
    except ServiceUnavailable:
        pass

    # Re-init does not work with MySQL due to issues with previously created connection
    # Considering that:
    # 1) this is a workaround to test the initialization
    #       (not the normal workflow used by the application)
    # 2) the init al already tests with any other DB, included postgres
    # 3) MySQL is not used by any project
    # => there is no need to go crazy in debugging this issue!
    if detector.authentication_service == "sqlalchemy" and auth.is_mysql():
        return False

    create_app(mode=ServerModes.INIT)

    auth = detector.get_authentication_instance()
    user = auth.get_user(username=BaseAuthentication.default_user)
    assert user is not None
