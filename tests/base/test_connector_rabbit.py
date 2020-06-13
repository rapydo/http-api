import time

import pytest

from restapi.exceptions import ServiceUnavailable
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_rabbit(app):

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
    assert rabbit.write_to_queue("test", "celery")
    rabbit.channel.close()
    # Channel is automatically open, if found closed
    assert rabbit.write_to_queue("test", "celery")
    # assert not rabbit.write_to_queue("test", "invalidqueue")

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
