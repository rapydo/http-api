# -*- coding: utf-8 -*-

from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_mongo():

    if not detector.check_availability('mongo'):
        log.warning("Skipping mongo test: service not available")
        return False

    detector.connectors_instances.get('mongo').get_instance()
