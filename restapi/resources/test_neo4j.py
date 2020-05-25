# -*- coding: utf-8 -*-

from flask_apispec import MethodResource
from marshmallow import fields
from flask_apispec import marshal_with

from restapi.rest.definition import EndpointResource
from restapi.models import Schema, Neo4jSchema, Neo4jChoice

from restapi.services.detect import detector
from restapi.exceptions import RestApiException
from restapi import decorators
from restapi.confs import TESTING
from restapi.connectors.neo4j import graph_transactions
from restapi.utilities.logs import log

if TESTING and detector.check_availability('neo4j'):

    from restapi.connectors.neo4j.models import User, Group

    CHOICES_tuple = (("A", "A"), ("B", "B"), ("C", "C"))
    CHOICES_dict = {"A": "A", "B": "B", "C": "C"}

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
        group1 = Neo4jSchema(Group, fields="*")
        group2 = Neo4jSchema(Group, fields=("*",))
        group3 = Neo4jSchema(Group, fields=["*"])
        group4 = Neo4jSchema(Group, fields=[])
        group5 = Neo4jSchema(Group, fields="")
        group6 = Neo4jSchema(Group, fields=None)

        choices1 = Neo4jChoice(CHOICES_tuple)
        choices2 = Neo4jChoice(CHOICES_dict)

    class TestNeo4j(MethodResource, EndpointResource):

        depends_on = ["NEO4J_ENABLE_CONNECTOR"]
        labels = ["tests"]

        _GET = {
            "/tests/neo4j/<test>": {
                "summary": "Execute tests against the neo4j connector",
                "description": "Only enabled in testing mode",
                "responses": {"200": {"description": "Tests executed"}},
            },
        }

        @decorators.catch_errors()
        @graph_transactions
        @marshal_with(Output, code=200)
        def get(self, test):
            self.neo4j = self.get_service_instance('neo4j')
            try:
                if test == "1":
                    log.info("First Test")
                    self.neo4j.cypher("MATCH (n) RETURN n LIMIT 1")
                elif test == "2":
                    log.info("Second Test")
                    self.neo4j.cypher("MATCH (n) RETURN n with a syntax error")
                else:
                    log.info("No Test")
            except Exception as e:
                raise RestApiException(str(e), status_code=400)
            return {"val": 1}
