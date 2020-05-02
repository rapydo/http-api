# -*- coding: utf-8 -*-

import os
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_sqlalchemy():

    if not detector.check_availability('sqlalchemy'):
        log.warning("Skipping sqlalchemy test: service not avaiable")
        return False

    sql = detector.connectors_instances.get('sqlalchemy').get_instance()

    return True
