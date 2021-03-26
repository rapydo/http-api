from restapi import decorators
from restapi.connectors import Connector
from restapi.endpoints.schemas import group_users_output
from restapi.exceptions import ServerError
from restapi.rest.definition import EndpointResource
from restapi.services.authentication import Role


class GroupUsers(EndpointResource):

    depends_on = ["MAIN_LOGIN_ENABLE"]
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

        user_group = user.belongs_to
        if Connector.authentication_service == "neo4j":
            user_group = user_group.single()

        data = []
        for user in user_group.members:

            data.append(user)

        return self.response(data)
