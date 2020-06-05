import pytest
from restapi.services.detect import detector
from restapi.exceptions import ServiceUnavailable
from restapi.utilities.logs import log


def test_rabbit():

    if not detector.check_availability('rabbitmq'):
        log.warning("Skipping rabbit test: service not available")
        return False

    try:
        detector.get_service_instance(
            "rabbitmq",
            host="invalidhostname",
            port=123
        )
        pytest.fail("No exception raised on unavailable service")
    except ServiceUnavailable:
        pass

    rabbit = detector.get_service_instance("rabbitmq")
    assert rabbit.write_to_queue("test", "celery")
