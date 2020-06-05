import pytest
from restapi.services.detect import detector
from restapi.exceptions import ServiceUnavailable
from restapi.utilities.logs import log


def test_sqlalchemy():

    if not detector.check_availability('sqlalchemy'):
        log.warning("Skipping sqlalchemy test: service not available")
        return False

    try:
        detector.get_service_instance(
            "sqlalchemy",
            host="invalidhostname",
            port=123
        )
        pytest.fail("No exception raised on unavailable service")
    except ServiceUnavailable:
        pass

    detector.get_service_instance("sqlalchemy")
