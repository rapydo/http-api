from restapi import decorators
from restapi.endpoints.schemas import group_users_output
from restapi.exceptions import ServerError
from restapi.rest.definition import EndpointResource
from restapi.services.authentication import Role


class GroupUsers(EndpointResource):

    depends_on = ["MAIN_LOGIN_ENABLE", "AUTH_ENABLE"]
    labels = ["admin"]

    @decorators.auth.require_all(Role.COORDINATOR)
    @decorators.marshal_with(group_users_output(), code=200)
    @decorators.endpoint(
        path="/group/users",
        summary="List of users of your group",
        responses={
            200: "List of users successfully retrieved",
        },
    )
    def get(self):

        user = self.get_user()

        # Can't happen since auth is required
        if not user:  # pragma: no cover
            raise ServerError("User misconfiguration")

        group = self.auth.get_user_group(user)

        return self.response(self.auth.get_group_members(group))
