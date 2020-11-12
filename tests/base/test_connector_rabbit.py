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

    exchange = faker.pystr()
    if obj.exchange_exists(exchange):
        obj.delete_exchange(exchange)

    queue = faker.pystr()
    if obj.queue_exists(queue):
        obj.delete_queue(queue)

    assert not obj.exchange_exists(queue)
    assert not obj.send("test", routing_key=queue, exchange=exchange)
    assert not obj.send_json("test", routing_key=queue, exchange=exchange)

    assert not obj.queue_exists(queue)
    assert not obj.send("test", routing_key=queue)
    assert not obj.send_json("test", routing_key=queue)
    obj.create_queue(queue)
    assert obj.queue_exists(queue)
    obj.create_queue(queue)

    # Now send works because queue exists
    assert obj.send("test", routing_key=queue)
    assert obj.send_json("test", routing_key=queue)

    # This send does not work because exchange does not exist
    assert not obj.send("test", routing_key=queue, exchange=exchange)
    assert not obj.send_json("test", routing_key=queue, exchange=exchange)

    obj.create_exchange(exchange)
    assert obj.exchange_exists(exchange)
    obj.create_exchange(exchange)

    # Now that exchange does exists, but the queue is not bound
    assert not obj.send("test", routing_key=queue, exchange=exchange)
    assert not obj.send_json("test", routing_key=queue, exchange=exchange)

    obj.queue_bind(queue, exchange, queue)

    assert obj.send("test", routing_key=queue, exchange=exchange)
    assert obj.send_json("test", routing_key=queue, exchange=exchange)

    obj.queue_unbind(queue, exchange, queue)

    assert not obj.send("test", routing_key=queue, exchange=exchange)
    assert not obj.send_json("test", routing_key=queue, exchange=exchange)

    obj.queue_bind(queue, exchange, queue)

    if obj.channel:
        obj.channel.close()

    # Channel is automatically opened, if found closed
    assert obj.send("test", queue)

    obj.delete_exchange(exchange)
    assert not obj.send("test", routing_key=queue, exchange=exchange)
    assert not obj.send_json("test", routing_key=queue, exchange=exchange)

    assert obj.send("test", routing_key=queue)
    assert obj.send_json("test", routing_key=queue)

    obj.delete_queue(queue)

    assert not obj.send("test", routing_key=queue)
    assert not obj.send_json("test", routing_key=queue)

    queue = faker.pystr()
    if obj.queue_exists(queue):
        obj.delete_queue(queue)

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
