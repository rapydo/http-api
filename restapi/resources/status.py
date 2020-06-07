from flask_apispec import MethodResource

from restapi import decorators
from restapi.rest.definition import EndpointResource


class Status(MethodResource, EndpointResource):
    """ Check if APIs are online """

    ALLOW_HTML_RESPONSE = True
    labels = ["helpers"]

    _GET = {
        "/status": {
            "summary": "Check if the API server is currently reachable",
            "description": "Use this endpoint to monitor network or server problems",
            "responses": {"200": {"description": "Server is alive"}},
        }
    }

    @decorators.catch_errors()
    def get(self, service=None):

        return self.response("Server is alive")


class AuthStatus(MethodResource, EndpointResource):
    """ Check if APIs are online """

    baseuri = "/auth"
    labels = ["helpers"]

    _GET = {
        "/status": {
            "summary": "Check if the provided auth token is valid",
            "description": "Use this endpoint to verify if an auth token is valid",
            "responses": {"200": {"description": "Auth token is valid"}},
        }
    }

    @decorators.catch_errors()
    @decorators.auth.required()
    def get(self, service=None):

        return self.response(True)
