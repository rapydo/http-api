# -*- coding: utf-8 -*-

from flask_apispec import MethodResource
from flask_apispec import marshal_with
from flask_apispec import use_kwargs
from marshmallow import fields, validate
from marshmallow import Schema as MarshmallowSchema
from restapi.models import Schema

from restapi import decorators
from restapi.rest.definition import EndpointResource
from restapi.exceptions import RestApiException
from restapi.connectors.neo4j import graph_transactions
from restapi.utilities.htmlcodes import hcodes
from restapi.services.detect import detector

from restapi.utilities.logs import log

if detector.check_availability('neo4j'):

    def get_users():
        auth_service = detector.authentication_service

        if auth_service == 'neo4j':

            neo4j = detector.get_service_instance('neo4j')

            users = {}
            for u in neo4j.User.nodes.all():

                label = "{} {} ({})".format(u.name, u.surname, u.email)
                users[u.uuid] = label

            return users

        if auth_service == 'sqlalchemy':
            return None

        if auth_service == 'mongo':
            return None

        log.error("Unknown auth service: {}", auth_service)  # pragma: no cover

    class Coordinator(MarshmallowSchema):
        uuid = fields.Str()
        email = fields.Email(required=True)
        name = fields.Str(required=True)
        surname = fields.Str(required=True)

    class Group(MarshmallowSchema):
        uuid = fields.Str()
        fullname = fields.Str()
        shortname = fields.Str()

        coordinator = fields.Nested(Coordinator)
        # prefix = fields.Str()

    class InputGroup(Schema):
        shortname = fields.Str(required=True, description='Short name')
        fullname = fields.Str(required=True, description='Full name')
        # prefix = fields.Str(required=True)

        users = get_users()
        coordinator = fields.Str(
            required=True,
            description='Select a coordinator',
            validate=validate.OneOf(
                choices=users.keys(),
                labels=users.values()
            )
        )

    def get_POST_input(request):
        return InputGroup(strip_required=False)

    def get_PUT_input(request):
        return InputGroup(strip_required=True)

    class AdminGroups(MethodResource, EndpointResource):

        labels = ["admin"]
        _GET = {
            "/admin/groups": {
                "summary": "List of groups",
                "responses": {
                    "200": {"description": "List of groups successfully retrieved"},
                },
            }
        }
        _POST = {
            "/admin/groups": {
                "summary": "Create a new group",
                "responses": {
                    "200": {"description": "The uuid of the new group is returned"},
                },
            }
        }
        _PUT = {
            "/admin/groups/<group_id>": {
                "summary": "Modify a group",
                "responses": {
                    "200": {"description": "Group successfully modified"},
                },
            }
        }
        _DELETE = {
            "/admin/groups/<group_id>": {
                "summary": "Delete a group",
                "responses": {
                    "200": {"description": "Group successfully deleted"},
                },
            }
        }

        @decorators.catch_errors()
        @decorators.catch_graph_exceptions
        @decorators.auth.required(roles=['admin_root'])
        @marshal_with(Group(many=True), code=200)
        def get(self):

            self.graph = self.get_service_instance('neo4j')
            groups = self.graph.Group.nodes.all().copy()
            for g in groups:
                g.coordinator = g.coordinator.single()
            return self.response(groups)

        @decorators.catch_errors()
        @decorators.catch_graph_exceptions
        @graph_transactions
        @decorators.auth.required(roles=['admin_root'])
        @use_kwargs(get_POST_input)
        def post(self, **kwargs):

            self.graph = self.get_service_instance('neo4j')

            coordinator_uuid = kwargs.pop('coordinator')
            coordinator = self.graph.User.nodes.get_or_none(uuid=coordinator_uuid)

            if coordinator is None:
                raise RestApiException(
                    'User not found', status_code=hcodes.HTTP_BAD_REQUEST
                )

            # GRAPH #
            group = self.graph.Group(**kwargs).save()
            group.coordinator.connect(coordinator)

            return self.response(group.uuid)

        @decorators.catch_errors()
        @decorators.catch_graph_exceptions
        @graph_transactions
        @decorators.auth.required(roles=['admin_root'])
        @use_kwargs(get_PUT_input)
        def put(self, group_id, **kwargs):

            self.graph = self.get_service_instance('neo4j')

            group = self.graph.Group.nodes.get_or_none(uuid=group_id)
            if group is None:
                raise RestApiException("Group not found")

            coordinator_uuid = kwargs.pop('coordinator', None)

            db = self.get_service_instance(detector.authentication_service)
            db.update_properties(group, kwargs, kwargs)

            group.save()

            if coordinator_uuid:

                coordinator = self.graph.User.nodes.get_or_none(uuid=coordinator_uuid)

                p = None
                for p in group.coordinator.all():
                    if p == coordinator:
                        continue

                if p is None:
                    group.coordinator.connect(coordinator)
                else:
                    group.coordinator.reconnect(p, coordinator)

            return self.empty_response()

        @decorators.catch_errors()
        @decorators.catch_graph_exceptions
        @graph_transactions
        @decorators.auth.required(roles=['admin_root'])
        def delete(self, group_id):

            self.graph = self.get_service_instance('neo4j')

            group = self.graph.Group.nodes.get_or_none(uuid=group_id)

            if group is None:
                raise RestApiException("Group not found")

            group.delete()

            return self.empty_response()
