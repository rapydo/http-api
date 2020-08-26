from restapi import decorators
from restapi.confs import TESTING
from restapi.exceptions import RestApiException
from restapi.models import Neo4jChoice, Neo4jSchema, Schema, fields
from restapi.rest.definition import EndpointResource
from restapi.services.detect import detector
from restapi.utilities.logs import log

if TESTING and detector.check_availability("neo4j"):

    from restapi.connectors.neo4j.models import Group, User

    CHOICES_tuple = (("A", "A"), ("B", "B"), ("C", "C"))
    CHOICES_dict = {"A": "A", "B": "B", "C": "C"}

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

        choices1 = Neo4jChoice(CHOICES_tuple)
        choices2 = Neo4jChoice(CHOICES_dict)

    class TestNeo4j(EndpointResource):

        depends_on = ["NEO4J_ENABLE_CONNECTOR"]
        labels = ["tests"]

        @decorators.graph_transactions
        @decorators.marshal_with(Output, code=200)
        @decorators.endpoint(
            path="/tests/neo4j/<test>",
            summary="Execute tests against the neo4j connector",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def get(self, test):
            self.neo4j = self.get_service_instance("neo4j")
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
                    n = self.neo4j.JustATest(p_str="")
                    n.save()
                    data["created"] = n.created
                    data["modified1"] = n.modified
                    n.save()
                    data["modified2"] = n.modified
                    return data
                else:
                    log.info("No Test")
            except Exception as e:
                raise RestApiException(str(e), status_code=400)
            return {"val": 1}
