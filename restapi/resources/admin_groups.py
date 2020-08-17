from restapi import decorators
from restapi.connectors.neo4j import graph_transactions
from restapi.exceptions import NotFound, Unauthorized
from restapi.models import InputSchema, Schema, fields, validate
from restapi.rest.definition import EndpointResource
from restapi.services.authentication import Role
from restapi.services.detect import detector
from restapi.utilities.logs import log

if detector.check_availability("neo4j"):

    def get_users():
        auth_service = detector.authentication_service

        if auth_service == "neo4j":

            neo4j = detector.get_service_instance("neo4j")

            users = {}
            for u in neo4j.User.nodes.all():

                label = f"{u.name} {u.surname} ({u.email})"
                users[u.uuid] = label

            return users

        if auth_service == "sqlalchemy":
            return None

        if auth_service == "mongo":
            return None

        log.error("Unknown auth service: {}", auth_service)  # pragma: no cover

    class Coordinator(Schema):
        uuid = fields.Str()
        email = fields.Email(required=True)
        name = fields.Str(required=True)
        surname = fields.Str(required=True)

    class Group(Schema):
        uuid = fields.Str()
        fullname = fields.Str()
        shortname = fields.Str()

        coordinator = fields.Nested(Coordinator)
        # prefix = fields.Str()

    class InputGroup(InputSchema):
        shortname = fields.Str(required=True, description="Short name")
        fullname = fields.Str(required=True, description="Full name")
        # prefix = fields.Str(required=True)

        users = get_users()
        coordinator = fields.Str(
            required=True,
            description="Select a coordinator",
            validate=validate.OneOf(choices=users.keys(), labels=users.values()),
        )

    def get_input_group(request):
        # if not request:
        #     return {}

        # return InputGroup(strip_required=request.method == "PUT")

        return InputGroup()

    class AdminGroups(EndpointResource):

        labels = ["admin"]
        _GET = {
            "/admin/groups": {
                "private": True,
                "summary": "List of groups",
                "responses": {
                    "200": {"description": "List of groups successfully retrieved"},
                    "409": {"description": "Request is invalid due to conflicts"},
                },
            }
        }
        _POST = {
            "/admin/groups": {
                "private": True,
                "summary": "Create a new group",
                "responses": {
                    "200": {"description": "The uuid of the new group is returned"},
                    "409": {"description": "Request is invalid due to conflicts"},
                },
            }
        }
        _PUT = {
            "/admin/groups/<group_id>": {
                "private": True,
                "summary": "Modify a group",
                "responses": {"200": {"description": "Group successfully modified"}},
            }
        }
        _DELETE = {
            "/admin/groups/<group_id>": {
                "private": True,
                "summary": "Delete a group",
                "responses": {"200": {"description": "Group successfully deleted"}},
            }
        }

        @decorators.auth.require_all(Role.ADMIN)
        @decorators.catch_graph_exceptions
        @decorators.marshal_with(Group(many=True), code=200)
        def get(self):

            self.graph = self.get_service_instance("neo4j")
            groups = self.graph.Group.nodes.all().copy()
            for g in groups:
                g.coordinator = g.coordinator.single()
            return self.response(groups)

        @decorators.auth.require_all(Role.ADMIN)
        @decorators.catch_graph_exceptions
        @graph_transactions
        @decorators.use_kwargs(get_input_group)
        def post(self, **kwargs):

            self.graph = self.get_service_instance("neo4j")

            coordinator_uuid = kwargs.pop("coordinator")
            coordinator = self.graph.User.nodes.get_or_none(uuid=coordinator_uuid)

            # Can not be tested because coordinator values are filtered by webargs
            # Only valid uuid will be provided here.
            # This is an extra-security check
            if not coordinator:  # pragma: no cover
                raise Unauthorized("User not found")

            # GRAPH #
            group = self.graph.Group(**kwargs).save()
            group.coordinator.connect(coordinator)

            return self.response(group.uuid)

        @decorators.auth.require_all(Role.ADMIN)
        @decorators.catch_graph_exceptions
        @graph_transactions
        @decorators.use_kwargs(get_input_group)
        def put(self, group_id, **kwargs):

            self.graph = self.get_service_instance("neo4j")

            group = self.graph.Group.nodes.get_or_none(uuid=group_id)
            if not group:
                raise NotFound("Group not found")

            coordinator_uuid = kwargs.pop("coordinator", None)

            db = self.get_service_instance(detector.authentication_service)
            db.update_properties(group, kwargs)

            group.save()

            if coordinator_uuid:

                coordinator = self.graph.User.nodes.get_or_none(uuid=coordinator_uuid)

                p = None
                for p in group.coordinator.all():
                    if p == coordinator:
                        continue

                # None can not be tested because coordinator is required in post
                # => it is not possible to have a group without a coordinator.
                # This is an extra security check
                if p is None:  # pragma: no cover
                    group.coordinator.connect(coordinator)
                else:
                    group.coordinator.reconnect(p, coordinator)

            return self.empty_response()

        @decorators.auth.require_all(Role.ADMIN)
        @decorators.catch_graph_exceptions
        @graph_transactions
        def delete(self, group_id):

            self.graph = self.get_service_instance("neo4j")

            group = self.graph.Group.nodes.get_or_none(uuid=group_id)

            if not group:
                raise NotFound("Group not found")

            group.delete()

            return self.empty_response()
