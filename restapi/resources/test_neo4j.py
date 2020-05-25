# -*- coding: utf-8 -*-

from flask_apispec import MethodResource
from flask_apispec import use_kwargs
from marshmallow import fields

from restapi.rest.definition import EndpointResource
from restapi.models import Schema, Neo4jSchema, Neo4jChoice

from restapi.services.detect import detector
from restapi.exceptions import RestApiException
from restapi import decorators
from restapi.confs import TESTING
from restapi.connectors.neo4j import graph_transactions


if TESTING and detector.check_availability('neo4j'):

    from restapi.connectors.neo4j.models import User, Group

    class Input(Schema):
        test = fields.Integer()

    CHOICES = (("A", "A"), ("B", "B"), ("C", "C"))

    class Output(Schema):
        val = fields.Integer()
        user = Neo4jSchema(
            User,
            fields=(
                'uuid',
                'email',
                'name',
                'surname',
                'is_active',
                'last_password_change',
            )
        )
        group = Neo4jSchema(Group, fields="*")
        choices = Neo4jChoice(CHOICES)

    class TestNeo4j(MethodResource, EndpointResource):

        depends_on = ["NEO4J_ENABLE_CONNECTOR"]
        labels = ["tests"]

        _GET = {
            "/tests/neo4j": {
                "summary": "Execute tests against the neo4j connector",
                "description": "Only enabled in testing mode",
                "responses": {"200": {"description": "Tests executed"}},
            },
        }

        @decorators.catch_errors()
        @graph_transactions
        @use_kwargs(Input, locations=['query'])
        def get(self, test=0):
            self.neo4j = self.get_service_instance('neo4j')
            try:
                if test == 1:
                    self.neo4j.cypher("MATCH (n) RETURN n LIMIT 1")
                elif test == 2:
                    self.neo4j.cypher("MATCH (n) RETURN n with a syntax error")
            except Exception as e:
                raise RestApiException(str(e), status_code=400)
            return 1
