import os
from restapi.server import create_app
from restapi.services.detect import detector
from restapi.services.authentication import BaseAuthentication
from restapi.utilities.logs import log

def test_destroy():

    # Only executed if tests are run with --destroy flag
    if value := os.getenv("TEST_DESTROY_MODE", '0') != '1':
        log.info(
            "Skipping destroy test, TEST_DESTROY_MODE is {}",
            value
        )
        return False

    if not detector.check_availability('authentication'):
        log.warning("Skipping authentication test: service not available")
        return False

    auth = detector.get_service_instance('authentication')

    user = auth.get_user_object(username=BaseAuthentication.default_user)
    assert user is not None

    create_app(destroy_mode=True)

    user = auth.get_user_object(username=BaseAuthentication.default_user)
    assert user is None

    create_app(init_mode=True)

    user = auth.get_user_object(username=BaseAuthentication.default_user)
    assert user is not None
