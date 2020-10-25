from restapi import decorators
from restapi.exceptions import NotFound, ServiceUnavailable, Unauthorized
from restapi.models import Schema, fields, validate
from restapi.rest.definition import EndpointResource
from restapi.services.authentication import Role
from restapi.services.detect import detector

# from restapi.utilities.logs import log

if detector.check_availability("neo4j"):

    # Used to serialize through the CoordinatorField
    class Coordinator(Schema):
        uuid = fields.UUID()
        email = fields.Email(required=True)
        name = fields.Str(required=True)
        surname = fields.Str(required=True)

    # This is required to convert neo4j relationship in a single element...
    class CoordinatorField(fields.Field):
        """Field that serializes from a coordinator list into one element"""

        def _serialize(self, value, attr, obj, **kwargs):

            if AdminGroups.neo4j_enabled:
                return Coordinator().dump(value.single())
            return Coordinator().dump(value)

    # This is also defined in profile.py and admin_users.py but without coordinator
    # Output Schema
    class Group(Schema):
        uuid = fields.UUID()
        fullname = fields.Str()
        shortname = fields.Str()

        coordinator = CoordinatorField()

    # Function required here to reload the model at runtime and fill the groups list
    # Note that these are callables returning a model, not models!
    # They will be executed a runtime
    def getInputSchema(request):

        if not request:
            return {}

        auth = EndpointResource.load_authentication()

        users = {}
        for u in auth.get_users():

            label = f"{u.name} {u.surname} ({u.email})"
            users[u.uuid] = label

        attributes = {}

        attributes["shortname"] = fields.Str(required=True, description="Short name")
        attributes["fullname"] = fields.Str(required=True, description="Full name")
        attributes["coordinator"] = fields.Str(
            required=True,
            description="Select a coordinator",
            validate=validate.OneOf(choices=users.keys(), labels=users.values()),
        )

        return Schema.from_dict(attributes)

    class AdminGroups(EndpointResource):

        auth_service = detector.authentication_service
        neo4j_enabled = auth_service == "neo4j"
        sql_enabled = auth_service == "sqlalchemy"
        mongo_enabled = auth_service == "mongo"

        labels = ["admin"]
        private = True

        @decorators.auth.require_all(Role.ADMIN)
        @decorators.catch_graph_exceptions
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
        @decorators.catch_graph_exceptions
        @decorators.graph_transactions
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

            coordinator_uuid = kwargs.pop("coordinator")
            coordinator = self.auth.get_user_object(user_id=coordinator_uuid)

            # Can not be tested because coordinator values are filtered by webargs
            # Only valid uuid will be provided here.
            # This is an extra-security check
            if not coordinator:  # pragma: no cover
                raise Unauthorized("Coordinator not found")

            group = self.auth.create_group(kwargs, coordinator)

            return self.response(group.uuid)

        @decorators.auth.require_all(Role.ADMIN)
        @decorators.catch_graph_exceptions
        @decorators.graph_transactions
        @decorators.use_kwargs(getInputSchema)
        @decorators.endpoint(
            path="/admin/groups/<group_id>",
            summary="Modify a group",
            responses={204: "Group successfully modified", 404: "Group not found"},
        )
        def put(self, group_id, **kwargs):

            group = self.auth.get_groups(group_id=group_id)
            if not group:
                raise NotFound("This group cannot be found")

            group = group[0]

            coordinator_uuid = kwargs.pop("coordinator", None)
            coordinator = self.auth.get_user_object(user_id=coordinator_uuid)

            self.auth.update_group(group, kwargs, coordinator)

            return self.empty_response()

        @decorators.auth.require_all(Role.ADMIN)
        @decorators.catch_graph_exceptions
        @decorators.graph_transactions
        @decorators.endpoint(
            path="/admin/groups/<group_id>",
            summary="Delete a group",
            responses={204: "Group successfully deleted", 404: "Group not found"},
        )
        def delete(self, group_id):

            group = self.auth.get_groups(group_id=group_id)
            if not group:
                raise NotFound("This group cannot be found")

            group = group[0]

            if self.neo4j_enabled or self.mongo_enabled:
                group.delete()
            elif self.sql_enabled:
                self.auth.db.session.delete(group)
                self.auth.db.session.commit()
            else:
                raise ServiceUnavailable(  # pragma: no cover
                    "Invalid auth backend, all known db are disabled"
                )

            return self.empty_response()
