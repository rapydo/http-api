# -*- coding: utf-8 -*-

from restapi.rest.definition import EndpointResource
from restapi.protocols.bearer import authentication


class Logout(EndpointResource):
    """ Let the logged user escape from here, invalidating current token """

    baseuri = "/auth"
    labels = ["authentication"]

    GET = {
        "/logout": {
            "summary": "Logout from current credentials",
            "description": "Invalidate current registered token",
            "responses": {"200": {"description": "Token correctly removed"}},
        }
    }

    @authentication.required()
    def get(self):
        self.auth.invalidate_token(token=self.auth.get_token())
        return self.empty_response()
