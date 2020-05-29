from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_pushpin():

    if not detector.check_availability('pushpin'):
        log.warning("Skipping pushpin test: service not available")
        return False

    detector.get_service_instance("pushpin")
