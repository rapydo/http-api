# -*- coding: utf-8 -*-

from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_pushpin():

    if not detector.check_availability('pushpin'):
        log.warning("Skipping pushpin test: service not available")
        return False

    detector.connectors_instances.get('pushpin').get_instance()
