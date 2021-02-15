from restapi import decorators
from restapi.rest.definition import EndpointResource, Response


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
    def get(self) -> Response:

        token = self.get_token()
        self.auth.invalidate_token(token)
        self.log_event(self.events.logout)
        return self.empty_response()
