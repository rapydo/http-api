from flask_apispec import MethodResource

from restapi import decorators
from restapi.rest.definition import EndpointResource


class Logout(MethodResource, EndpointResource):
    """ Let the logged user escape from here, invalidating current token """

    baseuri = "/auth"
    labels = ["authentication"]

    _GET = {
        "/logout": {
            "summary": "Logout from current credentials",
            "description": "Invalidate current registered token",
            "responses": {"204": {"description": "Token correctly removed"}},
        }
    }

    @decorators.catch_errors()
    @decorators.auth.required()
    def get(self):
        self.auth.invalidate_token(token=self.get_token())
        return self.empty_response()
