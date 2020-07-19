import time

import pytest

from restapi.exceptions import ServiceUnavailable
from restapi.services.detect import detector
from restapi.utilities.logs import log

CONNECTOR = "mongo"


def test_mongo(app):

    if not detector.check_availability(CONNECTOR):

        obj = detector.get_debug_instance(CONNECTOR)
        assert obj is None

        try:
            obj = detector.get_service_instance(CONNECTOR)
            pytest("No exception raised")
        except ServiceUnavailable:
            pass

        log.warning("Skipping {} tests: service not available", CONNECTOR)
        return False

    log.info("Executing {} tests", CONNECTOR)

    # Run this before the init_services,
    # get_debug_instance is able to load what is needed
    obj = detector.get_debug_instance(CONNECTOR)
    assert obj is not None

    detector.init_services(
        app=app, project_init=False, project_clean=False,
    )

    try:
        obj = detector.get_service_instance(
            CONNECTOR, test_connection=True, host="invalidhostname", port=123
        )
        # test_connection does not work, let's explicitly test it
        try:
            obj.Token.objects.first()
        except BaseException:
            raise ServiceUnavailable("")
        pytest.fail("No exception raised on unavailable service")
    except ServiceUnavailable:
        pass

    obj = detector.get_service_instance(CONNECTOR, test_connection=True,)
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

    # test connection... and should fail
    # ???

    # ... close connection again ... nothing should happens
    obj.disconnect()

    with detector.get_service_instance(CONNECTOR) as obj:
        assert obj is not None

    obj = detector.get_debug_instance(CONNECTOR)
    assert obj is not None

    obj = detector.get_debug_instance("invalid")
    assert obj is None
