import time

import pytest

from restapi.connectors import pushpin as connector
from restapi.exceptions import ServiceUnavailable
from restapi.services.detect import detector
from restapi.utilities.logs import log

CONNECTOR = "pushpin"


def test_pushpin(app):

    if not detector.check_availability(CONNECTOR):

        obj = detector.get_debug_instance(CONNECTOR)
        assert obj is None

        try:
            obj = connector.get_instance()
            pytest.fail("No exception raised")
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
        app=app,
        project_init=False,
        project_clean=False,
    )

    try:
        connector.get_instance(host="invalidhostname", port=123)
        pytest.fail("No exception raised on unavailable service")
    except ServiceUnavailable:
        pass

    obj = connector.get_instance()
    assert obj is not None

    obj = connector.get_instance(expiration=1)
    obj_id = id(obj)

    obj = connector.get_instance(expiration=1)
    assert id(obj) == obj_id

    time.sleep(1)

    obj = connector.get_instance(expiration=1)
    assert id(obj) != obj_id

    assert obj.is_connected()
    obj.disconnect()
    assert not obj.is_connected()

    # ... close connection again ... nothing should happens
    obj.disconnect()

    with connector.get_instance() as obj:
        assert obj is not None

    obj = detector.get_debug_instance(CONNECTOR)
    assert obj is not None

    obj = detector.get_debug_instance("invalid")
    assert obj is None
