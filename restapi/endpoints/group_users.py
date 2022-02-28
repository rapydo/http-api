from restapi import decorators
from restapi.endpoints.schemas import group_users_output
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import Role, User


class GroupUsers(EndpointResource):

    depends_on = ["MAIN_LOGIN_ENABLE", "AUTH_ENABLE"]
    labels = ["management"]

    @decorators.auth.require_all(Role.COORDINATOR)
    @decorators.marshal_with(group_users_output(), code=200)
    @decorators.endpoint(
        path="/group/users",
        summary="List of users of your group",
        description="This endpoint is restricted to Group Coordinators",
        responses={
            200: "List of users successfully retrieved",
        },
    )
    def get(self, user: User) -> Response:

        group = self.auth.get_user_group(user)

        members = self.auth.get_group_members(group)

        if self.auth.is_admin(user):
            return self.response(members)

        # Requested by a non-admin, filtering out admins
        members = [m for m in members if not self.auth.is_admin(m)]
        return self.response(members)
