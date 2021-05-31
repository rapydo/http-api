from restapi import decorators
from restapi.config import TESTING
from restapi.connectors import Connector, neo4j, sqlalchemy
from restapi.models import fields
from restapi.rest.definition import EndpointResource, Response

# from restapi.utilities.logs import log

if TESTING:

    class TestVulnerabilities(EndpointResource):

        labels = ["tests"]

        def do_queries(self, value: str) -> None:

            # Temporary disabled
            value = "value"

            # This is just a stub... to be completed
            if Connector.check_availability("neo4j"):
                graph = neo4j.get_instance()

                graph.cypher(f"MATCH (u: User) WHERE u.name = '{value}' return u.name")
                graph.cypher(f'MATCH (u: User) WHERE u.name = "{value}" return u.name')
                graph.cypher(f"MATCH (u: User) return u.name as {value}")
                graph.cypher(f"MATCH (u: User) return u.name as {value}")
                graph.User.nodes.get_or_none(name=value)

            elif Connector.check_availability("sqlalchemy"):
                sql = sqlalchemy.get_instance()

                sql.db.engine.execute(f"SELECT name FROM user WHERE name = '{value}'")
                sql.db.engine.execute(f'SELECT name FROM user WHERE name = "{value}"')
                sql.db.engine.execute(f"SELECT name as {value} FROM user")
                sql.db.engine.execute(f"SELECT name as {value} FROM user")
                sql.User.query.filter_by(name=value).first()

        @decorators.use_kwargs({"payload": fields.Str(required=True)}, location="query")
        @decorators.endpoint(
            path="/tests/vulnerabilities/<urlvalue>",
            summary="Execute tests against known vulnerabilities",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def get(self, urlvalue: str, payload: str) -> Response:

            self.do_queries(urlvalue)
            self.do_queries(payload)

            return self.response(True)

        @decorators.use_kwargs({"payload": fields.Str(required=True)})
        @decorators.endpoint(
            path="/tests/vulnerabilities/<urlvalue>",
            summary="Execute tests against known vulnerabilities",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def post(self, urlvalue: str, payload: str) -> Response:

            self.do_queries(urlvalue)
            self.do_queries(payload)
            return self.response(True)
