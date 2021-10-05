from restapi import decorators
from restapi.config import TESTING
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import User

if TESTING:

    class TestParametersInjections(EndpointResource):
        @decorators.auth.require()
        @decorators.endpoint(
            path="/tests/inject/<param>",
            summary="Verify injected parameters",
            description="Only enabled in testing mode",
            responses={200: "Tests executed"},
        )
        def get(
            self, param: str, user: User, unknown: str = "default_value"
        ) -> Response:

            return self.response([user.email, param, unknown])
