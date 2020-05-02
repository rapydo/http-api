# -*- coding: utf-8 -*-

import os
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_rabbit():

    if not detector.check_availability('rabbit'):
        log.warning("Skipping rabbit test: service not avaiable")
        return False

    rabbit = detector.connectors_instances.get('rabbit').get_instance()

    return True
