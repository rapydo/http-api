import time

import pytest
from flask import Flask

from restapi.connectors import pushpin as connector
from restapi.exceptions import ServiceUnavailable
from restapi.services.detect import detector
from restapi.utilities.logs import log

CONNECTOR = "pushpin"


def test_pushpin(app: Flask) -> None:

    if not detector.check_availability(CONNECTOR):

        try:
            obj = connector.get_instance()
            pytest.fail("No exception raised")  # pragma: no cover
        except ServiceUnavailable:
            pass
        log.warning("Skipping {} tests: service not available", CONNECTOR)
        return None

    log.info("Executing {} tests", CONNECTOR)

    detector.init_services(
        app=app,
        project_init=False,
        project_clean=False,
    )

    try:
        connector.get_instance(host="invalidhostname", port=123)
        pytest.fail("No exception raised on unavailable service")  # pragma: no cover
    except ServiceUnavailable:
        pass

    obj = connector.get_instance()
    assert obj is not None

    obj.disconnect()

    # a second disconnect should not raise any error
    obj.disconnect()

    # Create new connector with short expiration time
    obj = connector.get_instance(expiration=2, verification=1)
    obj_id = id(obj)

    # Connector is expected to be still valid
    obj = connector.get_instance(expiration=2, verification=1)
    assert id(obj) == obj_id

    time.sleep(1)

    # The connection should have been checked and should be still valid
    obj = connector.get_instance(expiration=2, verification=1)
    assert id(obj) == obj_id

    time.sleep(1)

    # Connection should have been expired and a new connector been created
    obj = connector.get_instance(expiration=2, verification=1)
    assert id(obj) != obj_id

    assert obj.is_connected()
    obj.disconnect()
    assert not obj.is_connected()

    # ... close connection again ... nothing should happens
    obj.disconnect()

    with connector.get_instance() as obj:
        assert obj is not None
