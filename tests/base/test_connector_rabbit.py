# -*- coding: utf-8 -*-

from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_rabbit():

    if not detector.check_availability('rabbit'):
        log.warning("Skipping rabbit test: service not available")
        return False

    rabbit = detector.connectors_instances.get('rabbit').get_instance()
    assert rabbit.write_to_queue("test", "celery")
