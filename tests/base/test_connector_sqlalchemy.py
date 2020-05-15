# -*- coding: utf-8 -*-

from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_sqlalchemy():

    if not detector.check_availability('sqlalchemy'):
        log.warning("Skipping sqlalchemy test: service not available")
        return False

    connector = detector.connectors_instances.get('sqlalchemy')
    if connector is None:
        log.warning("Skipping sqlalchemy test: connector not available")
        return False

    connector.get_instance()
