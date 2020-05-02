# -*- coding: utf-8 -*-

import os
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_mongo():

    if not detector.check_availability('mongo'):
        log.warning("Skipping mongo test: service not avaiable")
        return False

    mongo = detector.connectors_instances.get('mongo').get_instance()

    return True
