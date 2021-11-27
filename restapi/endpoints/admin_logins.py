from restapi import decorators
from restapi.endpoints.schemas import LoginsSchema
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import Role, User


class AdminLogins(EndpointResource):

    depends_on = ["MAIN_LOGIN_ENABLE", "AUTH_ENABLE"]
    labels = ["admin"]
    private = True

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.marshal_with(LoginsSchema(many=True), code=200)
    @decorators.endpoint(
        path="/admin/logins",
        summary="Retrieve logins information",
        responses={"200": "Logins data retrieved"},
    )
    def get(self, user: User) -> Response:

        logins = self.auth.get_logins(username=None, only_unflushed=False)
        return self.response(logins)
