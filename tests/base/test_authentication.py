# -*- coding: utf-8 -*-
from restapi.connectors.authentication import HandleSecurity
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_authentication():

    if not detector.check_availability('authentication'):
        log.warning("Skipping authentication test: service not avaiable")
        return False

    auth = detector.connectors_instances.get('authentication').get_instance()
    security = HandleSecurity(auth)

    return True
