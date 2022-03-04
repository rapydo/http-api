from restapi import decorators
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import User


class Status(EndpointResource):

    labels = ["status"]

    @decorators.endpoint(
        path="/status",
        summary="Check if the API server is currently reachable",
        description="Use this endpoint to monitor network or server problems",
        responses={200: "Server is alive"},
    )
    def get(self) -> Response:

        return self.response("Server is alive", allow_html=True)


class AuthStatus(EndpointResource):

    depends_on = ["AUTH_ENABLE"]
    labels = ["authentication"]

    @decorators.auth.require()
    @decorators.endpoint(
        path="/auth/status",
        summary="Verify the validity of the provided token",
        description="Use this endpoint to verify if an auth token is valid",
        responses={200: "Auth token is valid"},
    )
    def get(self, user: User) -> Response:

        return self.response(True)
