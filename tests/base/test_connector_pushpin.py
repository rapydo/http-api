# -*- coding: utf-8 -*-
from glom import glom
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_pushpin():

    if not detector.check_availability('pushpin'):
        log.warning("Skipping pushpin test: service not available")
        return False

    glom(detector.services, "pushpin.instance").get_instance()
