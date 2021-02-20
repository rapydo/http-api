from typing import Any

from restapi import decorators
from restapi.exceptions import NotFound
from restapi.models import Schema, fields
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import Role


class User(Schema):
    uuid = fields.UUID()
    email = fields.Email()
    name = fields.String()
    surname = fields.String()


# Output Schema
class Group(Schema):
    uuid = fields.UUID()
    fullname = fields.Str()
    shortname = fields.Str()

    members = fields.Nested(User(many=True))


class GroupInput(Schema):
    shortname = fields.Str(required=True, description="Short name")
    fullname = fields.Str(required=True, description="Full name")


class AdminGroups(EndpointResource):

    labels = ["admin"]
    private = True

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.marshal_with(Group(many=True), code=200)
    @decorators.endpoint(
        path="/admin/groups",
        summary="List of groups",
        responses={
            200: "List of groups successfully retrieved",
            409: "Request is invalid due to conflicts",
        },
    )
    def get(self) -> Response:

        groups = self.auth.get_groups()

        return self.response(groups)

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.use_kwargs(GroupInput)
    @decorators.endpoint(
        path="/admin/groups",
        summary="Create a new group",
        responses={
            200: "The uuid of the new group is returned",
            409: "Request is invalid due to conflicts",
        },
    )
    def post(self, **kwargs: Any) -> Response:

        group = self.auth.create_group(kwargs)

        self.auth.save_group(group)

        self.log_event(self.events.create, group, kwargs)
        return self.response(group.uuid)

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.use_kwargs(GroupInput)
    @decorators.endpoint(
        path="/admin/groups/<group_id>",
        summary="Modify a group",
        responses={204: "Group successfully modified", 404: "Group not found"},
    )
    def put(self, group_id: str, **kwargs: Any) -> Response:

        group = self.auth.get_group(group_id=group_id)
        if not group:
            raise NotFound("This group cannot be found")

        self.auth.db.update_properties(group, kwargs)

        self.auth.save_group(group)

        self.log_event(self.events.modify, group, kwargs)

        return self.empty_response()

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.endpoint(
        path="/admin/groups/<group_id>",
        summary="Delete a group",
        responses={204: "Group successfully deleted", 404: "Group not found"},
    )
    def delete(self, group_id: str) -> Response:

        group = self.auth.get_group(group_id=group_id)
        if not group:
            raise NotFound("This group cannot be found")

        self.auth.delete_group(group)

        self.log_event(self.events.delete, group)

        return self.empty_response()
