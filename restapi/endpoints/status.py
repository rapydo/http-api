from restapi import decorators
from restapi.rest.definition import EndpointResource


class Status(EndpointResource):
    """ Check if APIs are online """

    ALLOW_HTML_RESPONSE = True
    labels = ["helpers"]

    @decorators.endpoint(
        path="/status",
        summary="Check if the API server is currently reachable",
        description="Use this endpoint to monitor network or server problems",
        responses={200: "Server is alive"},
    )
    def get(self, service=None):

        return self.response("Server is alive")


class AuthStatus(EndpointResource):
    """ Check if APIs are online """

    baseuri = "/auth"
    labels = ["helpers"]

    @decorators.auth.require()
    @decorators.endpoint(
        path="/status",
        summary="Check if the provided auth token is valid",
        description="Use this endpoint to verify if an auth token is valid",
        responses={200: "Auth token is valid"},
    )
    def get(self, service=None):

        return self.response(True)
