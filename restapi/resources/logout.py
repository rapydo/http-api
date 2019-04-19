# -*- coding: utf-8 -*-

from restapi.rest.definition import EndpointResource


class Logout(EndpointResource):
    """ Let the logged user escape from here, invalidating current token """

    def get(self):
        self.auth.invalidate_token(token=self.auth.get_token())
        return self.empty_response()
