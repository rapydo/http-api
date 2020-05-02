# -*- coding: utf-8 -*-

import os
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_pushpin():

    if not detector.check_availability('pushpin'):
        log.warning("Skipping pushpin test: service not avaiable")
        return False

    pushpin = detector.connectors_instances.get('pushpin').get_instance()

    return True
