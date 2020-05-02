# -*- coding: utf-8 -*-

import os
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_celery():

    if not detector.check_availability('celery'):
        log.warning("Skipping celery test: service not avaiable")
        return False

    celery = detector.connectors_instances.get('celery').get_instance()

    return True
