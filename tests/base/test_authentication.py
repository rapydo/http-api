# -*- coding: utf-8 -*-

import os
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_authentication():

    if not detector.check_availability('authentication'):
        log.warning("Skipping authentication test: service not avaiable")
        return False

    auth = detector.connectors_instances.get('authentication').get_instance()

    return True
