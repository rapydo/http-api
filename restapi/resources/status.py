from restapi import decorators
from restapi.models import InputSchema, fields
from restapi.rest.definition import EndpointResource
from restapi.utilities.logs import log


class Sub(InputSchema):
    a = fields.Str(required=True)


class Test(InputSchema):
    # class Meta:
    #     unknown = INCLUDE
    x = fields.Str(required=True)
    y = fields.Nested(Sub(), required=True)


class Status(EndpointResource):
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

    @decorators.use_kwargs(Test)
    def get(self, service=None, **kwargs):

        log.critical(kwargs)

        return self.response("Server is alive")


class AuthStatus(EndpointResource):
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

    @decorators.auth.require()
    def get(self, service=None):

        return self.response(True)
