import time

import pytest

from restapi.connectors import rabbitmq as connector
from restapi.exceptions import ServiceUnavailable
from restapi.services.detect import detector
from restapi.utilities.logs import log

CONNECTOR = "rabbitmq"


def test_rabbit(app, faker):

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
        connector.get_instance(host="invalidhostname", port=123)
        pytest.fail("No exception raised on unavailable service")
    except ServiceUnavailable:
        pass

    obj = connector.get_instance()
    assert obj is not None

    queue = faker.pystr()
    if obj.queue_exists(queue):
        obj.delete_queue(queue)

    assert not obj.queue_exists(queue)
    assert not obj.send("test", queue)
    assert not obj.send_json("test", queue)
    obj.create_queue(queue)
    assert obj.queue_exists(queue)
    obj.create_queue(queue)

    assert obj.send("test", queue)
    assert obj.send_json("test", queue)

    if obj.channel:
        obj.channel.close()

    # Channel is automatically open, if found closed
    assert obj.send("test", queue)
    obj.delete_queue(queue)

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

    # Connection is closed, of course
    assert not obj.send("test", queue)
    assert not obj.send_json("test", queue)

    # ... close connection again ... nothing should happens
    obj.disconnect()

    with connector.get_instance() as obj:
        assert obj is not None
