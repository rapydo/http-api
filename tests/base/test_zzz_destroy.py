import os
from restapi.server import create_app
from restapi.utilities.logs import log

def test_destroy():

    # Only executed if tests are run with --destroy flag
    value = os.getenv("TEST_DESTROY_MODE", '0')
    if value == '1':
        create_app(destroy_mode=True)
        create_app(init_mode=True)
    else:
        log.info(
            "Skipping destroy test, TEST_DESTROY_MODE is {}",
            value
        )
