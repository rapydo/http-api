from restapi import decorators
from restapi.config import TESTING
from restapi.connectors import Connector, neo4j
from restapi.exceptions import BadRequest
from restapi.models import Neo4jSchema, Schema, fields
from restapi.rest.definition import EndpointResource, Response
from restapi.utilities.logs import log

if TESTING and Connector.check_availability("neo4j"):

    from neomodel import (
        IntegerProperty,
        StringProperty,
        StructuredNode,
        UniqueIdProperty,
    )

    from restapi.connectors.neo4j.models import Group, User

    CHOICES_tuple = (("A", "A"), ("B", "B"), ("C", "C"))
    CHOICES_dict = {"A": "A", "B": "B", "C": "C"}

    # Base type StructuredNode becomes "Any" due to an unfollowed import
    class Custom(StructuredNode):  # type: ignore
        custom = StringProperty(required=True, choices=CHOICES_tuple)
        myint = IntegerProperty(required=True)
        # do not set it as required because:
        # ValueError: required argument ignored by UniqueIdProperty
        myuuid = UniqueIdProperty()

    class Output(Schema):
        val = fields.Integer()
        created = fields.DateTime()
        modified1 = fields.DateTime()
        modified2 = fields.DateTime()
        user = Neo4jSchema(
            User,
            fields=(
                "uuid",
                "email",
                "name",
                "surname",
                "is_active",
                "last_password_change",
            ),
        )
        group1 = Neo4jSchema(Group, fields="*")
        group2 = Neo4jSchema(Group, fields=("*",))
        group3 = Neo4jSchema(Group, fields=["*"])
        group4 = Neo4jSchema(Group, fields=[])
        group5 = Neo4jSchema(Group, fields=["fullname", "shortname"])
        group6 = Neo4jSchema(Group, fields="")
        group7 = Neo4jSchema(Group, fields=None)
        custom = Neo4jSchema(Custom, fields="*")

        choices1 = fields.Neo4jChoice(CHOICES_tuple)
        choices2 = fields.Neo4jChoice(CHOICES_dict)

    class TestNeo4j(EndpointResource):

        depends_on = ["NEO4J_ENABLE_CONNECTOR"]
        labels = ["tests"]

        @decorators.marshal_with(Output, code=200)
        @decorators.endpoint(
            path="/tests/neo4j/<test>",
            summary="Execute tests against the neo4j connector",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def get(self, test: str) -> Response:
            self.neo4j = neo4j.get_instance()
            try:
                if test == "1":
                    log.info("First Test")
                    self.neo4j.cypher("MATCH (n) RETURN n LIMIT 1")
                elif test == "2":
                    log.info("Second Test")
                    self.neo4j.cypher("MATCH (n) RETURN n with a syntax error")
                # This test will verify that a timestamped node when saved
                # Automatically update the modified attribute
                elif test == "3":
                    data = {}
                    n = self.neo4j.NodeTest(p_str="")
                    n.save()
                    data["created"] = n.created
                    data["modified1"] = n.modified
                    n.save()
                    data["modified2"] = n.modified
                    return self.response(data)
                else:
                    log.info("No Test")
            except Exception as e:
                raise BadRequest(str(e))
            return self.response({"val": 1})
