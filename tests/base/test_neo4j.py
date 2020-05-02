# -*- coding: utf-8 -*-

import os
from restapi.services.detect import detector
from restapi.utilities.logs import log


def test_neo4j():

    if not detector.check_availability('neo4j'):
        log.warning("Skipping neo4j test: service not avaiable")
        return False

    neo4j = detector.connectors_instances.get('neo4j').get_instance()

    return True
