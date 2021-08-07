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

            neo4j_enabled = Connector.check_availability("neo4j")
            sql_enabled = Connector.check_availability("sqlalchemy")
            mysql_enabled = sql_enabled and sqlalchemy.SQLAlchemy.is_mysql()
            postgres_enabled = sql_enabled and not sqlalchemy.SQLAlchemy.is_mysql()

            # This is just a stub... to be completed
            if neo4j_enabled:
                graph = neo4j.get_instance()

                graph.cypher(
                    "MATCH (g: Group) WHERE g.shortname = $value return g.shortname",
                    value=value,
                )

                graph.Group.nodes.get_or_none(shortname=value)

            elif postgres_enabled:
                sql = sqlalchemy.get_instance()

                t = sqlalchemy.text('SELECT * FROM "group" WHERE shortname = :value')
                sql.db.engine.execute(t, value=value)

                sql.Group.query.filter_by(shortname=value).first()

            elif mysql_enabled:
                sql = sqlalchemy.get_instance()

                t = sqlalchemy.text("SELECT * FROM `group` WHERE shortname = :value")
                sql.db.engine.execute(t, value=value)

                sql.Group.query.filter_by(shortname=value).first()

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
