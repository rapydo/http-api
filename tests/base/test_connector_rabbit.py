import time

import pytest

from restapi.exceptions import ServiceUnavailable
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_rabbit(app, faker):

    if not detector.check_availability("rabbitmq"):
        log.warning("Skipping rabbit test: service not available")
        return False

    detector.init_services(
        app=app, project_init=False, project_clean=False,
    )

    try:
        detector.get_service_instance("rabbitmq", host="invalidhostname", port=123)
        pytest.fail("No exception raised on unavailable service")
    except ServiceUnavailable:
        pass

    rabbit = detector.get_service_instance("rabbitmq")
    assert rabbit is not None

    queue = faker.pystr()
    if rabbit.queue_exists(queue):
        rabbit.delete_queue(queue)

    assert not rabbit.queue_exists(queue)
    assert not rabbit.write_to_queue("test", queue)
    rabbit.create_queue(queue)
    assert rabbit.queue_exists(queue)
    rabbit.create_queue(queue)

    assert rabbit.write_to_queue("test", queue)

    rabbit.channel.close()

    # Channel is automatically open, if found closed
    assert rabbit.write_to_queue("test", queue)

    rabbit = detector.get_service_instance("rabbitmq", cache_expiration=1)
    obj_id = id(rabbit)

    rabbit = detector.get_service_instance("rabbitmq", cache_expiration=1)
    assert id(rabbit) == obj_id

    time.sleep(1)

    rabbit = detector.get_service_instance("rabbitmq", cache_expiration=1)
    assert id(rabbit) != obj_id

    # Close connection...
    rabbit.disconnect()

    # Connection is closed, of course
    assert not rabbit.write_to_queue("test", "celery")

    # ... close connection again ... nothing should happens
    rabbit.disconnect()

    with detector.get_service_instance("rabbitmq") as obj:
        assert obj is not None
