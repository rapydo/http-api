import time

import pytest

from restapi.exceptions import ServiceUnavailable
from restapi.services.detect import detector
from restapi.utilities.logs import log

CONNECTOR = "pushpin"


def test_pushpin(app):

    if not detector.check_availability(CONNECTOR):

        obj = detector.get_debug_instance(CONNECTOR)
        assert obj is None

        log.warning("Skipping pushpin test: service not available")
        return False

    # Run this before the init_services,
    # get_debug_instance is able to load what is needed
    obj = detector.get_debug_instance(CONNECTOR)
    assert obj is not None

    detector.init_services(
        app=app, project_init=False, project_clean=False,
    )

    try:
        detector.get_service_instance(CONNECTOR, host="invalidhostname", port=123)
        pytest.fail("No exception raised on unavailable service")
    except ServiceUnavailable:
        pass

    obj = detector.get_service_instance(CONNECTOR)
    assert obj is not None

    obj = detector.get_service_instance(CONNECTOR, cache_expiration=1)
    obj_id = id(obj)

    obj = detector.get_service_instance(CONNECTOR, cache_expiration=1)
    assert id(obj) == obj_id

    time.sleep(1)

    obj = detector.get_service_instance(CONNECTOR, cache_expiration=1)
    assert id(obj) != obj_id

    # Close connection...
    obj.disconnect()

    # Test connection... should fail!
    # ??

    # ... close connection again ... nothing should happens
    obj.disconnect()

    with detector.get_service_instance(CONNECTOR) as obj:
        assert obj is not None

    obj = detector.get_debug_instance(CONNECTOR)
    assert obj is not None

    obj = detector.get_debug_instance("invalid")
    assert obj is None
