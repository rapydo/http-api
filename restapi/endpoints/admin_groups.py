from restapi import decorators
from restapi.exceptions import NotFound
from restapi.models import Schema, fields
from restapi.rest.definition import EndpointResource
from restapi.services.authentication import Role
from restapi.services.detect import detector


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


# Function required here to reload the model at runtime and fill the groups list
# Note that these are callables returning a model, not models!
# They will be executed a runtime
def getInputSchema(request):

    if not request:
        return Schema.from_dict({})

    auth = detector.get_authentication_instance()

    users = {}
    for u in auth.get_users():

        label = f"{u.name} {u.surname} ({u.email})"
        users[u.uuid] = label

    attributes = {}

    attributes["shortname"] = fields.Str(required=True, description="Short name")
    attributes["fullname"] = fields.Str(required=True, description="Full name")

    return Schema.from_dict(attributes)


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
    def get(self):

        groups = self.auth.get_groups()

        return self.response(groups)

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.use_kwargs(getInputSchema)
    @decorators.endpoint(
        path="/admin/groups",
        summary="Create a new group",
        responses={
            200: "The uuid of the new group is returned",
            409: "Request is invalid due to conflicts",
        },
    )
    def post(self, **kwargs):

        group = self.auth.create_group(kwargs)

        self.auth.save_group(group)

        return self.response(group.uuid)

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.use_kwargs(getInputSchema)
    @decorators.endpoint(
        path="/admin/groups/<group_id>",
        summary="Modify a group",
        responses={204: "Group successfully modified", 404: "Group not found"},
    )
    def put(self, group_id, **kwargs):

        group = self.auth.get_group(group_id=group_id)
        if not group:
            raise NotFound("This group cannot be found")

        self.auth.db.update_properties(group, kwargs)

        self.auth.save_group(group)

        return self.empty_response()

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.endpoint(
        path="/admin/groups/<group_id>",
        summary="Delete a group",
        responses={204: "Group successfully deleted", 404: "Group not found"},
    )
    def delete(self, group_id):

        group = self.auth.get_group(group_id=group_id)
        if not group:
            raise NotFound("This group cannot be found")

        self.auth.delete_group(group)

        return self.empty_response()
