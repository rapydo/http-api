# -*- coding: utf-8 -*-

from restapi.rest.definition import EndpointResource


class Logout(EndpointResource):
    """ Let the logged user escape from here, invalidating current token """
    baseuri = "/auth"
    labels = ["authentication"]

    SPECS = {
        "mapping": {
            "tologout": "/logout"
        }
    }

    GET = {
        "tologout": {
            "summary": "Logout from current credentials",
            "description": "Invalidate current registered token",
            "custom": {
                "authentication": True
            },
            "responses": {
                "200": {
                    "description": "Token correctly removed"
                }
            }
        }
    }

    def get(self):
        self.auth.invalidate_token(token=self.auth.get_token())
        return self.empty_response()
