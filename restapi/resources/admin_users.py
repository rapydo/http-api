# -*- coding: utf-8 -*-

from restapi import decorators as decorate
from restapi.services.neo4j.graph_endpoints import GraphBaseOperations
from restapi.exceptions import RestApiException
# from restapi.services.neo4j.graph_endpoints import graph_transactions
# from restapi.services.neo4j.graph_endpoints import catch_graph_exceptions
from restapi.services.authentication import BaseAuthentication
from restapi.services.detect import detector
from utilities import htmlcodes as hcodes

from utilities.logs import get_logger
log = get_logger(__name__)

__author__ = "Mattia D'Antonio (m.dantonio@cineca.it)"


class AdminUsers(GraphBaseOperations):

    def link_role(self, user, properties):
        ids = self.parseAutocomplete(
            properties, 'roles', id_key='name', split_char=',')
        # log.critical(ids)

        if ids is None:
            return

        for p in user.roles.all():
            user.roles.disconnect(p)

        for id in ids:
            try:
                role = self.graph.Role.nodes.get(name=id)
                user.roles.connect(role)
            except self.graph.Role.DoesNotExist:
                pass

    def parse_group(self, v):
        groups = self.parseAutocomplete(v, 'group', id_key='id')

        if groups is None:
            raise RestApiException(
                'Group not found', status_code=hcodes.HTTP_BAD_REQUEST)

        group_id = groups.pop()
        group = self.graph.Group.nodes.get_or_none(uuid=group_id)

        if group is None:
            raise RestApiException(
                'Group not found', status_code=hcodes.HTTP_BAD_REQUEST)

        return group

    def check_permissions(self, user, node, is_admin, is_group_admin):

        if node is None:
            return False

        # an ADMIN is always authorized
        if is_admin:
            return True

        # You are neither an ADMIN nor a GROUP ADMIN
        if not is_group_admin:
            return False

        # If you are not an ADMIN, you cannot modify yourself...
        # use the profile instead!
        if user == node:
            return False

        # FIXME: only implemented for neo4j
        # You are a group admin... but the group mathes??
        for g in user.coordinator.all():
            if node.belongs_to.is_connected(g):
                return True

        return False

    @decorate.catch_error()
    # @catch_graph_exceptions
    def get(self, id=None):

        data = []
        if not detector.check_availability('neo4j'):
            log.warning("This endpoint is implemented only for neo4j")
            return self.force_response(data)

        self.graph = self.get_service_instance('neo4j')

        is_admin = self.auth.verify_admin()
        is_group_admin = self.auth.verify_group_admin()
        if not is_admin and not is_group_admin:
            raise RestApiException(
                "You are not authorized: missing privileges",
                status_code=hcodes.HTTP_BAD_UNAUTHORIZED)

        current_user = self.get_current_user()
        nodeset = self.graph.User.nodes

        for n in nodeset.all():

            is_authorized = self.check_permissions(
                current_user, n, is_admin, is_group_admin
            )
            if not is_authorized:
                continue

            user = self.getJsonResponse(n, max_relationship_depth=2)
            data.append(user)

        return self.force_response(data)

    @decorate.catch_error()
    # @catch_graph_exceptions
    # @graph_transactions
    def post(self):

        v = self.get_input()
        if len(v) == 0:
            raise RestApiException(
                'Empty input',
                status_code=hcodes.HTTP_BAD_REQUEST)

        if not detector.check_availability('neo4j'):
            log.warning("This endpoint is implemented only for neo4j")
            return self.force_response('0')

        self.graph = self.get_service_instance('neo4j')

        is_admin = self.auth.verify_admin()
        is_group_admin = self.auth.verify_group_admin()
        if not is_admin and not is_group_admin:
            raise RestApiException(
                "You are not authorized: missing privileges",
                status_code=hcodes.HTTP_BAD_UNAUTHORIZED)

        schema = self.get_endpoint_custom_definition()
        # INIT #
        properties = self.read_properties(schema, v)

        group = None
        if 'group' in v:
            group = self.parse_group(v)

        # GRAPH #
        properties["authmethod"] = "credentials"
        if "password" in properties:
            properties["password"] = \
                BaseAuthentication.hash_password(properties["password"])
        # properties["name_surname"] = \
        #     self.createUniqueIndex(
        #         properties["name"], properties["surname"])
        user = self.graph.User(**properties).save()

        if group is not None:
            if not is_admin:
                raise RestApiException(
                    "Check if you are allowed to assign users to this group")

            user.belongs_to.connect(group)

        if not is_admin:
            raise RestApiException(
                "Check if you are allowed to assign users to this role")
        self.link_role(user, v)

        return self.force_response(user.uuid)

    @decorate.catch_error()
    # @catch_graph_exceptions
    # @graph_transactions
    def put(self, user_id=None):

        if user_id is None:

            raise RestApiException(
                "Please specify a user id",
                status_code=hcodes.HTTP_BAD_REQUEST)

        if not detector.check_availability('neo4j'):
            log.warning("This endpoint is implemented only for neo4j")
            return self.empty_response()

        schema = self.get_endpoint_custom_definition()
        self.graph = self.get_service_instance('neo4j')

        is_admin = self.auth.verify_admin()
        is_group_admin = self.auth.verify_group_admin()
        if not is_admin and not is_group_admin:
            raise RestApiException(
                "You are not authorized: missing privileges",
                status_code=hcodes.HTTP_BAD_UNAUTHORIZED)

        v = self.get_input()

        user = self.graph.User.nodes.get_or_none(uuid=user_id)
        # user = self.getNode(self.graph.User, user_id, field='uuid')
        if user is None:
            raise RestApiException(
                "This user cannot be found or you are not authorized")

        current_user = self.get_current_user()
        is_authorized = self.check_permissions(
            current_user, user, is_admin, is_group_admin
        )
        if not is_authorized:
            raise RestApiException(
                "This user cannot be found or you are not authorized")

        if "password" in v and v["password"] == "":
            del v["password"]
        else:
            v["password"] = BaseAuthentication.hash_password(v["password"])

        self.update_properties(user, schema, v)
        user.name_surname = self.createUniqueIndex(user.name, user.surname)
        user.save()

        if 'group' in v:

            group = self.parse_group(v)

            if not is_admin:
                raise RestApiException(
                    "Check if you are allowed to assign users to this group")

            p = None
            for p in user.belongs_to.all():
                if p == group:
                    continue

            if p is not None:
                user.belongs_to.reconnect(p, group)
            else:
                user.belongs_to.connect(group)

        if not is_admin:
            raise RestApiException(
                "Check if you are allowed to assign users to this role")

        self.link_role(user, v)

        return self.empty_response()

    @decorate.catch_error()
    # @catch_graph_exceptions
    # @graph_transactions
    def delete(self, user_id=None):

        if user_id is None:

            raise RestApiException(
                "Please specify a user id",
                status_code=hcodes.HTTP_BAD_REQUEST)

        if not detector.check_availability('neo4j'):
            log.warning("This endpoint is implemented only for neo4j")
            return self.empty_response()

        self.graph = self.get_service_instance('neo4j')

        is_admin = self.auth.verify_admin()
        is_group_admin = self.auth.verify_group_admin()
        if not is_admin and not is_group_admin:
            raise RestApiException(
                "You are not authorized: missing privileges",
                status_code=hcodes.HTTP_BAD_UNAUTHORIZED)

        user = self.graph.User.nodes.get_or_none(uuid=user_id)
        # user = self.getNode(self.graph.User, user_id, field='uuid')
        if user is None:
            raise RestApiException(
                "This user cannot be found or you are not authorized")

        current_user = self.get_current_user()
        is_authorized = self.check_permissions(
            current_user, user, is_admin, is_group_admin
        )
        if not is_authorized:
            raise RestApiException(
                "This user cannot be found or you are not authorized")

        user.delete()

        return self.empty_response()
