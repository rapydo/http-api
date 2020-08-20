from restapi import decorators
from restapi.rest.definition import EndpointResource


class Logout(EndpointResource):
    """ Let the logged user escape from here, invalidating current token """

    baseuri = "/auth"
    labels = ["authentication"]

    @decorators.auth.require()
    @decorators.endpoint(
        path="/logout",
        summary="Logout from current credentials",
        description="Invalidate current registered token",
        responses={204: "Token correctly removed"},
    )
    def get(self):
        self.auth.invalidate_token(token=self.get_token())
        return self.empty_response()
