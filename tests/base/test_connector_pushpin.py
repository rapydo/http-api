import time

import pytest

from restapi.exceptions import ServiceUnavailable
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_pushpin(app):

    if not detector.check_availability("pushpin"):
        log.warning("Skipping pushpin test: service not available")
        return False

    detector.init_services(
        app=app, project_init=False, project_clean=False,
    )

    try:
        detector.get_service_instance("pushpin", host="invalidhostname", port=123)
        pytest.fail("No exception raised on unavailable service")
    except ServiceUnavailable:
        pass

    pushpin = detector.get_service_instance("pushpin")
    assert pushpin is not None

    pushpin = detector.get_service_instance("pushpin", cache_expiration=1)
    obj_id = id(pushpin)

    pushpin = detector.get_service_instance("pushpin", cache_expiration=1)
    assert id(pushpin) == obj_id

    time.sleep(1)

    pushpin = detector.get_service_instance("pushpin", cache_expiration=1)
    assert id(pushpin) != obj_id

    # Close connection...
    pushpin.disconnect()

    # Test connection... should fail!
    # ??

    # ... close connection again ... nothing should happens
    pushpin.disconnect()

    with detector.get_service_instance("pushpin") as obj:
        assert obj is not None
