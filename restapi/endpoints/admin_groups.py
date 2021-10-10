from typing import Any, Dict, List

from restapi import decorators
from restapi.connectors import Connector
from restapi.endpoints.schemas import GroupWithMembers, admin_group_input
from restapi.exceptions import NotFound
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import Group, Role, User


def inject_group(endpoint: EndpointResource, group_id: str) -> Dict[str, Any]:

    group = endpoint.auth.get_group(group_id=group_id)
    if not group:
        raise NotFound("This group cannot be found")

    return {"group": group}


class AdminGroups(EndpointResource):

    depends_on = ["AUTH_ENABLE"]
    labels = ["admin"]
    private = True

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.marshal_with(GroupWithMembers(many=True), code=200)
    @decorators.endpoint(
        path="/admin/groups",
        summary="List of groups",
        responses={
            200: "List of groups successfully retrieved",
            409: "Request is invalid due to conflicts",
        },
    )
    def get(self, user: User) -> Response:

        groups: List[Dict[str, Any]] = []

        for g in self.auth.get_groups():

            if Connector.authentication_service == "mongo":
                # mypy correctly raises errors because User is not defined
                # in generic Connector instances (as auth.db is)...
                # but in mongo connector the User model is properly injected
                UserModel = self.auth.db.User  # type: ignore
                members = UserModel.objects.raw({"belongs_to": g.id}).all()
            else:
                members = list(g.members)
            coordinators = [u for u in members if self.auth.is_coordinator(u)]

            groups.append(
                {
                    "uuid": g.uuid,
                    "shortname": g.shortname,
                    "fullname": g.fullname,
                    "members": members,
                    "coordinators": coordinators,
                }
            )

        return self.response(groups)

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.database_transaction
    @decorators.use_kwargs(admin_group_input)
    @decorators.endpoint(
        path="/admin/groups",
        summary="Create a new group",
        responses={
            200: "The uuid of the new group is returned",
            409: "Request is invalid due to conflicts",
        },
    )
    def post(self, user: User, **kwargs: Any) -> Response:

        group = self.auth.create_group(kwargs)

        self.auth.save_group(group)

        self.log_event(self.events.create, group, kwargs)
        return self.response(group.uuid)

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.preload(callback=inject_group)
    @decorators.database_transaction
    @decorators.use_kwargs(admin_group_input)
    @decorators.endpoint(
        path="/admin/groups/<group_id>",
        summary="Modify a group",
        responses={204: "Group successfully modified", 404: "Group not found"},
    )
    def put(self, group_id: str, group: Group, user: User, **kwargs: Any) -> Response:

        # mypy correctly raises errors because update_properties is not defined
        # in generic Connector instances, but in this case this is an instance
        # of an auth db and their implementation always contains this method
        self.auth.db.update_properties(group, kwargs)  # type: ignore

        self.auth.save_group(group)

        self.log_event(self.events.modify, group, kwargs)

        return self.empty_response()

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.preload(callback=inject_group)
    @decorators.endpoint(
        path="/admin/groups/<group_id>",
        summary="Delete a group",
        responses={204: "Group successfully deleted", 404: "Group not found"},
    )
    def delete(self, group_id: str, group: Group, user: User) -> Response:

        self.auth.delete_group(group)

        self.log_event(self.events.delete, group)

        return self.empty_response()
