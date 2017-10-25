# -*- coding: utf-8 -*-

from restapi import decorators as decorate
from restapi.services.neo4j.graph_endpoints import GraphBaseOperations
from restapi.exceptions import RestApiException
from restapi.services.neo4j.graph_endpoints import graph_transactions
from restapi.services.neo4j.graph_endpoints import catch_graph_exceptions
from restapi.services.authentication import BaseAuthentication
from utilities import htmlcodes as hcodes

from utilities.logs import get_logger
logger = get_logger(__name__)

__author__ = "Mattia D'Antonio (m.dantonio@cineca.it)"


class AdminUsers(GraphBaseOperations):

    def link_role(self, user, properties):
        ids = self.parseAutocomplete(
            properties, 'roles', id_key='name', split_char=',')
        logger.critical(ids)

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

    @decorate.catch_error()
    @catch_graph_exceptions
    def get(self, id=None):

        self.initGraph()
        nodeset = self.graph.User.nodes

        data = []
        for n in nodeset.all():
            user = self.getJsonResponse(n, max_relationship_depth=2)
            data.append(user)

        return self.force_response(data)

    @decorate.catch_error()
    @catch_graph_exceptions
    @graph_transactions
    def post(self):

        self.initGraph()

        v = self.get_input()
        if len(v) == 0:
            raise RestApiException(
                'Empty input',
                status_code=hcodes.HTTP_BAD_REQUEST)

        schema = self.get_endpoint_custom_definition()
        # INIT #
        properties = self.read_properties(schema, v)

        groups = self.parseAutocomplete(v, 'group', id_key='id')

        if groups is None:
            raise RestApiException(
                'Group not found', status_code=hcodes.HTTP_BAD_REQUEST)

        group_id = groups.pop()

        group = self.graph.Group.nodes.get_or_none(uuid=group_id)
        # group = self.getNode(self.graph.Group, group_id, field='uuid')

        if group is None:
            raise RestApiException(
                'Group not found', status_code=hcodes.HTTP_BAD_REQUEST)

        # GRAPH #
        properties["authmethod"] = "credentials"
        # if "password" in properties:
        properties["password"] = \
            BaseAuthentication.hash_password(properties["password"])
        # properties["name_surname"] = \
        #     self.createUniqueIndex(properties["name"], properties["surname"])
        user = self.graph.User(**properties).save()
        user.belongs_to.connect(group)
        self.link_role(user, v)

        return self.force_response(user.uuid)

    @decorate.catch_error()
    @catch_graph_exceptions
    @graph_transactions
    def put(self, user_id=None):

        if user_id is None:

            raise RestApiException(
                "Please specify a user id",
                status_code=hcodes.HTTP_BAD_REQUEST)

        schema = self.get_endpoint_custom_definition()
        self.initGraph()

        v = self.get_input()

        user = self.graph.User.nodes.get_or_none(uuid=user_id)
        # user = self.getNode(self.graph.User, user_id, field='uuid')
        if user is None:
            raise RestApiException("User not found")

        if "password" in v and v["password"] == "":
            del v["password"]
        else:
            v["password"] = BaseAuthentication.hash_password(v["password"])

        self.update_properties(user, schema, v)
        user.name_surname = self.createUniqueIndex(user.name, user.surname)
        user.save()
        groups = self.parseAutocomplete(v, 'group', id_key='id')

        if groups is not None:
            group_id = groups.pop()

            group = self.graph.Group.nodes.get_or_none(uuid=group_id)
            # group = self.getNode(self.graph.Group, group_id, field='uuid')

            p = None
            for p in user.belongs_to.all():
                if p == group:
                    continue

            if p is not None:
                user.belongs_to.reconnect(p, group)
            else:
                user.belongs_to.connect(group)
        self.link_role(user, v)

        return self.empty_response()

    @decorate.catch_error()
    @catch_graph_exceptions
    @graph_transactions
    def delete(self, user_id=None):

        if user_id is None:

            raise RestApiException(
                "Please specify a user id",
                status_code=hcodes.HTTP_BAD_REQUEST)

        self.initGraph()

        user = self.graph.User.nodes.get_or_none(uuid=user_id)
        # user = self.getNode(self.graph.User, user_id, field='uuid')
        if user is None:
            raise RestApiException('This user cannot be found')

        user.delete()

        return self.empty_response()


class UserRole(GraphBaseOperations):
    @decorate.catch_error(exception=Exception, catch_generic=True)
    @catch_graph_exceptions
    def get(self, query=None):

        self.initGraph()

        data = []
        cypher = "MATCH (r:Role)"

        if query is not None:
            cypher += " WHERE r.description <> 'automatic'"
            cypher += " AND r.name =~ '(?i).*%s.*'" % query

        cypher += " RETURN r ORDER BY r.name ASC"

        if query is None:
            cypher += " LIMIT 20"

        result = self.graph.cypher(cypher)
        for row in result:
            r = self.graph.Role.inflate(row[0])
            data.append({"name": r.name, "description": r.description})

        return self.force_response(data)
