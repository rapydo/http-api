import time

import pytest

from restapi.exceptions import ServiceUnavailable
from restapi.services.detect import detector
from restapi.utilities.logs import log

CONNECTOR = "rabbitmq"


def test_rabbit(app, faker):

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
        app=app,
        project_init=False,
        project_clean=False,
    )

    try:
        detector.get_service_instance(CONNECTOR, host="invalidhostname", port=123)
        pytest.fail("No exception raised on unavailable service")
    except ServiceUnavailable:
        pass

    obj = detector.get_service_instance(CONNECTOR)
    assert obj is not None

    queue = faker.pystr()
    if obj.queue_exists(queue):
        obj.delete_queue(queue)

    assert not obj.queue_exists(queue)
    assert not obj.write_to_queue("test", queue)
    obj.create_queue(queue)
    assert obj.queue_exists(queue)
    obj.create_queue(queue)

    assert obj.write_to_queue("test", queue)

    obj.channel.close()

    # Channel is automatically open, if found closed
    assert obj.write_to_queue("test", queue)
    obj.delete_queue(queue)

    obj = detector.get_service_instance(CONNECTOR, cache_expiration=1)
    obj_id = id(obj)

    obj = detector.get_service_instance(CONNECTOR, cache_expiration=1)
    assert id(obj) == obj_id

    time.sleep(1)

    obj = detector.get_service_instance(CONNECTOR, cache_expiration=1)
    assert id(obj) != obj_id

    assert obj.is_connected()
    obj.disconnect()
    assert not obj.is_connected()

    # Connection is closed, of course
    assert not obj.write_to_queue("test", queue)

    # ... close connection again ... nothing should happens
    obj.disconnect()

    with detector.get_service_instance(CONNECTOR) as obj:
        assert obj is not None

    obj = detector.get_debug_instance(CONNECTOR)
    assert obj is not None

    obj = detector.get_debug_instance("invalid")
    assert obj is None
