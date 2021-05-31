from restapi import decorators
from restapi.config import TESTING
from restapi.connectors import Connector, neo4j, sqlalchemy
from restapi.rest.definition import EndpointResource, Response

# from restapi.utilities.logs import log

if TESTING:

    class TestVulnerabilities(EndpointResource):

        labels = ["tests"]

        @decorators.endpoint(
            path="/tests/vulnerabilities/<test>",
            summary="Execute tests against known vulnerabilities",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def get(self, test: str) -> Response:

            # This is just a stub... to be completed
            if Connector.check_availability("neo4j"):
                graph = neo4j.get_instance()
                graph.cypher(f"MATCH (u: User) WHERE u.name = '{test}' return u")
                graph.cypher(f'MATCH (u: User) WHERE u.name = "{test}" return u')
                graph.User.nodes.get_or_none(name=test)
            elif Connector.check_availability("sqlalchemy"):
                sql = sqlalchemy.get_instance()
                sql.execute(f"SELECT * FROM User WHERE u.name = '{test}'")
                sql.execute(f'SELECT * FROM User WHERE u.name = "{test}"')
                sql.User.query.filter_by(name=test).first()

            return self.response(True)
