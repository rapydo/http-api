# -*- coding: utf-8 -*-
from glom import glom
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_sqlalchemy():

    if not detector.check_availability('sqlalchemy'):
        log.warning("Skipping sqlalchemy test: service not available")
        return False

    connector = glom(detector.services, "sqlalchemy.instance")
    if connector is None:
        log.warning("Skipping sqlalchemy test: connector not available")
        return False

    connector.get_instance()
