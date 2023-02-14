import time
from unittest.mock import patch

import pytest
from faker import Faker
from flask import Flask

from restapi.connectors import Connector
from restapi.connectors import rabbitmq as connector
from restapi.exceptions import ServiceUnavailable
from restapi.utilities.logs import log

CONNECTOR = "rabbitmq"
CONNECTOR_AVAILABLE = Connector.check_availability(CONNECTOR)


@pytest.mark.skipif(
    CONNECTOR_AVAILABLE, reason=f"This test needs {CONNECTOR} to be not available"
)
def test_no_rabbit() -> None:
    with pytest.raises(ServiceUnavailable):
        connector.get_instance()

    log.warning("Skipping {} tests: service not available", CONNECTOR)
    return None


@pytest.mark.skipif(
    not CONNECTOR_AVAILABLE, reason=f"This test needs {CONNECTOR} to be available"
)
def test_rabbit(app: Flask, faker: Faker) -> None:
    log.info("Executing {} tests", CONNECTOR)

    with pytest.raises(ServiceUnavailable):
        connector.get_instance(host="invalidhostname", port="123")

    obj = connector.get_instance()
    assert obj is not None

    exchange = faker.pystr()
    # This is useful for local tests, on CI the exchange never exists
    if obj.exchange_exists(exchange):  # pragma: no cover
        obj.delete_exchange(exchange)

    queue = faker.pystr()
    # This is useful for local tests, on CI the queue never exists
    if obj.queue_exists(queue):  # pragma: no cover
        obj.delete_queue(queue)

    assert not obj.queue_exists(queue)
    assert not obj.send(b"test", routing_key=queue)
    assert not obj.send_json("test", routing_key=queue)
    obj.create_queue(queue)
    assert obj.queue_exists(queue)
    obj.create_queue(queue)

    # Now send works because queue exists
    assert obj.send(b"test", routing_key=queue)
    assert obj.send_json("test", routing_key=queue)

    assert not obj.exchange_exists(exchange)
    assert obj.get_bindings(exchange) is None
    # This send does not work because exchange does not exist
    assert not obj.send(b"test", routing_key=queue, exchange=exchange)
    assert not obj.send_json("test", routing_key=queue, exchange=exchange)

    obj.create_exchange(exchange)
    assert obj.exchange_exists(exchange)
    obj.create_exchange(exchange)

    # Now the exchange exists, but the queue is not bound
    bindings = obj.get_bindings(exchange)
    assert isinstance(bindings, list)
    assert len(bindings) == 0
    assert not obj.send(b"test", routing_key=queue, exchange=exchange)
    assert not obj.send_json("test", routing_key=queue, exchange=exchange)

    obj.queue_bind(queue, exchange, queue)
    bindings = obj.get_bindings(exchange)
    assert bindings is not None
    assert len(bindings) == 1
    assert bindings[0]["exchange"] == exchange
    assert bindings[0]["routing_key"] == queue
    assert bindings[0]["queue"] == queue

    assert obj.send(b"test", routing_key=queue, exchange=exchange)
    assert obj.send_json("test", routing_key=queue, exchange=exchange)

    obj.queue_unbind(queue, exchange, queue)
    bindings = obj.get_bindings(exchange)
    assert isinstance(bindings, list)
    assert len(bindings) == 0

    assert not obj.send(b"test", routing_key=queue, exchange=exchange)
    assert not obj.send_json("test", routing_key=queue, exchange=exchange)

    obj.queue_bind(queue, exchange, queue)
    bindings = obj.get_bindings(exchange)
    assert bindings is not None
    assert len(bindings) == 1
    assert bindings[0]["exchange"] == exchange
    assert bindings[0]["routing_key"] == queue
    assert bindings[0]["queue"] == queue

    if obj.channel:
        obj.channel.close()

    # Channel is automatically opened, if found closed
    assert obj.send(b"test", queue)

    obj.delete_exchange(exchange)
    assert not obj.send(b"test", routing_key=queue, exchange=exchange)
    assert not obj.send_json("test", routing_key=queue, exchange=exchange)

    assert obj.send(b"test", routing_key=queue)
    assert obj.send_json("test", routing_key=queue)

    obj.delete_queue(queue)

    assert not obj.send(b"test", routing_key=queue)
    assert not obj.send_json("test", routing_key=queue)

    obj.disconnect()

    # a second disconnect should not raise any error
    obj.disconnect()

    assert obj.get_hostname("rabbit.dockerized.io") == "localhost"
    assert obj.get_hostname("anything.dockerized.io") == "localhost"
    assert obj.get_hostname("any.external.url") == "any.external.url"
    assert obj.get_hostname("1.1.1.1") == "1.1.1.1"
    assert obj.get_hostname("test") == "test"
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

    # ... close connection again ... nothing should happen
    obj.disconnect()

    with connector.get_instance() as obj:
        assert obj is not None

    with pytest.raises(ServiceUnavailable, match=r"Invalid retry value: 0"):
        connector.get_instance(retries=0, retry_wait=0)
    with pytest.raises(ServiceUnavailable, match=r"Invalid retry value: -1"):
        connector.get_instance(retries=-1, retry_wait=0)
    with pytest.raises(ServiceUnavailable, match=r"Invalid retry wait value: -1"):
        connector.get_instance(retries=1, retry_wait=-1)
    obj = connector.get_instance(retries=1, retry_wait=0)
    assert obj is not None

    MOCKED_RETURN = connector.get_instance()
    # Clean the cache
    Connector.disconnect_all()
    WAIT = 1
    with patch.object(Connector, "initialize_connection") as mock:
        start = time.time()
        mock.side_effect = [
            ServiceUnavailable("first"),
            ServiceUnavailable("second"),
            MOCKED_RETURN,
        ]
        obj = connector.get_instance(retries=10, retry_wait=WAIT)

        assert mock.call_count == 3
        assert obj == MOCKED_RETURN
        end = time.time()

        assert end - start > WAIT
