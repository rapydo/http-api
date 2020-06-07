import pytest

from restapi.exceptions import ServiceUnavailable
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_pushpin(app):

    if not detector.check_availability("pushpin"):
        log.warning("Skipping pushpin test: service not available")
        return False

    detector.init_services(
        app=app, project_init=False, project_clean=False,
    )

    try:
        detector.get_service_instance("pushpin", host="invalidhostname", port=123)
        pytest.fail("No exception raised on unavailable service")
    except ServiceUnavailable:
        pass

    pushpin = detector.get_service_instance("pushpin")
    assert pushpin is not None
