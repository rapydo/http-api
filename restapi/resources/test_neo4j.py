# -*- coding: utf-8 -*-

from flask_apispec import MethodResource
from restapi.rest.definition import EndpointResource
from restapi.services.detect import detector
from restapi.connectors.neo4j import graph_transactions
from restapi.utilities.globals import mem


if mem.TESTING and detector.check_availability('neo4j'):
    class TestNeo4j(MethodResource, EndpointResource):

        depends_on = ["CELERY_ENABLE"]
        labels = ["tests"]

        _GET = {
            "/tests/neo4j": {
                "summary": "Execute tests against the neo4j connector",
                "description": "Only enabled in testing mode",
                "responses": {"200": {"description": "Tests executed"}},
            },
        }

        @graph_transactions
        def get(self):
            return 1
