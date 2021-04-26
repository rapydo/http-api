"""
This test is intended to be executed as second-last, just before the re-init test
(this is why it is prefixed as zzz1)
Beware: if env TEST_DESTROY_MODE == 1 this test will destroy your database, be careful
"""
import os

from restapi.connectors import Connector
from restapi.env import Env
from restapi.exceptions import ServiceUnavailable
from restapi.server import ServerModes, create_app
from restapi.services.authentication import BaseAuthentication
from restapi.utilities.logs import log


def test_destroy() -> None:

    if not Env.get_bool("AUTH_ENABLED"):
        log.warning("Skipping destroy tests")
        return

    # Only executed if tests are run with --destroy flag
    if os.getenv("TEST_DESTROY_MODE", "0") != "1":
        log.info("Skipping destroy test, TEST_DESTROY_MODE not enabled")
        return

    # Always enabled during core tests
    if not Connector.check_availability("authentication"):  # pragma: no cover
        log.warning("Skipping authentication test: service not available")
        return

    auth = Connector.get_authentication_instance()

    user = auth.get_user(username=BaseAuthentication.default_user)
    assert user is not None

    create_app(mode=ServerModes.DESTROY)

    try:
        auth = Connector.get_authentication_instance()
        user = auth.get_user(username=BaseAuthentication.default_user)
        assert user is None
    except ServiceUnavailable:
        pass
