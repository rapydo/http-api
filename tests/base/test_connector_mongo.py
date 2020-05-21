# -*- coding: utf-8 -*-
from glom import glom
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_mongo():

    if not detector.check_availability('mongo'):
        log.warning("Skipping mongo test: service not available")
        return False

    glom(detector.services, "mongo.instance").get_instance()
