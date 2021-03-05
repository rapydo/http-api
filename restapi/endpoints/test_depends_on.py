from restapi import decorators
from restapi.config import TESTING
from restapi.rest.definition import EndpointResource, Response

if TESTING:

    # This endpoint is activated only if neo4j is enabled
    class TestDependsOn(EndpointResource):

        labels = ["tests"]
        depends_on = ["NEO4J_ENABLE"]

        @decorators.endpoint(
            path="/tests/depends_on/neo4j",
            summary="Execute tests on depends on option",
            description="Only enabled in testing mode",
            responses={
                200: "Content sent",
            },
        )
        def get(self) -> Response:

            return self.response("1")

    # This endpoint is activated only if neo4j is NOT enabled
    class TestDependsOnNOT(EndpointResource):

        labels = ["tests"]
        depends_on = ["not NEO4J_ENABLE"]

        @decorators.endpoint(
            path="/tests/depends_on_not/neo4j",
            summary="Execute tests on depends on option",
            description="Only enabled in testing mode",
            responses={
                200: "Content sent",
            },
        )
        def get(self) -> Response:

            return self.response("1")
