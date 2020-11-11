import time

import pytest

from restapi.connectors import mongo as connector
from restapi.exceptions import ServiceUnavailable
from restapi.services.detect import detector
from restapi.utilities.logs import log

CONNECTOR = "mongo"


def test_mongo(app):

    if not detector.check_availability(CONNECTOR):

        try:
            obj = connector.get_instance()
            pytest.fail("No exception raised")
        except ServiceUnavailable:
            pass

        log.warning("Skipping {} tests: service not available", CONNECTOR)
        return False

    log.info("Executing {} tests", CONNECTOR)

    detector.init_services(
        app=app,
        project_init=False,
        project_clean=False,
    )

    try:
        obj = connector.get_instance(host="invalidhostname", port=123)
        try:
            obj.Token.objects.first()
        except BaseException:
            raise ServiceUnavailable("")
        pytest.fail("No exception raised on unavailable service")
    except ServiceUnavailable:
        pass

    obj = connector.get_instance()
    assert obj is not None

    obj = connector.get_instance(expiration=1)
    obj_id = id(obj)

    obj = connector.get_instance(expiration=1)
    assert id(obj) == obj_id

    time.sleep(2)

    obj = connector.get_instance(expiration=1)
    assert id(obj) != obj_id

    assert obj.is_connected()
    obj.disconnect()
    assert not obj.is_connected()

    # ... close connection again ... nothing should happens
    obj.disconnect()

    with connector.get_instance() as obj:
        assert obj is not None
