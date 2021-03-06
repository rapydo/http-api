from restapi import decorators
from restapi.rest.definition import EndpointResource, Response


class Status(EndpointResource):
    """ Check if APIs are online """

    labels = ["helpers"]

    @decorators.endpoint(
        path="/status",
        summary="Check if the API server is currently reachable",
        description="Use this endpoint to monitor network or server problems",
        responses={200: "Server is alive"},
    )
    def get(self) -> Response:

        return self.response("Server is alive", allow_html=True)


class AuthStatus(EndpointResource):
    """ Check if APIs are online """

    depends_on = ["AUTH_ENABLE"]
    labels = ["helpers"]

    @decorators.auth.require()
    @decorators.endpoint(
        path="/auth/status",
        summary="Check if the provided auth token is valid",
        description="Use this endpoint to verify if an auth token is valid",
        responses={200: "Auth token is valid"},
    )
    def get(self) -> Response:

        return self.response(True)
