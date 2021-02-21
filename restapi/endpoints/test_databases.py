from restapi import decorators
from restapi.config import TESTING
from restapi.rest.definition import EndpointResource, Response

# from restapi.utilities.logs import log

if TESTING:

    # This endpoint will try to create database object with unique keys
    # A duplicated entry exception will be raised and catched by the
    # database_transaction that will restore previous modifications
    class TestDatabase(EndpointResource):

        labels = ["tests"]

        @decorators.database_transaction
        @decorators.endpoint(
            path="/tests/database/<data>",
            summary="Execute tests on database functionalities",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def post(self, data: str) -> Response:
            # self.neo4j = neo4j.get_instance()
            return self.response(True)
