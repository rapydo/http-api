# -*- coding: utf-8 -*-
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_sqlalchemy():

    if not detector.check_availability('sqlalchemy'):
        log.warning("Skipping sqlalchemy test: service not available")
        return False

    detector.get_service_instance("sqlalchemy")
