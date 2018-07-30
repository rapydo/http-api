# -*- coding: utf-8 -*-

from restapi import decorators as decorate
from restapi.services.neo4j.graph_endpoints import GraphBaseOperations
from restapi.exceptions import RestApiException
from restapi.services.neo4j.graph_endpoints import graph_transactions
from restapi.services.neo4j.graph_endpoints import catch_graph_exceptions
from restapi.services.authentication import BaseAuthentication
from restapi.services.detect import detector
from restapi.services.mail import send_mail, send_mail_is_active
from restapi.services.mail import get_html_template
from utilities import htmlcodes as hcodes

from utilities.globals import mem

from utilities.logs import get_logger
log = get_logger(__name__)

__author__ = "Mattia D'Antonio (m.dantonio@cineca.it)"


class AdminUsers(GraphBaseOperations):

    def parse_roles(self, properties):

        if 'roles' in properties:
            return self.parseAutocomplete(
                properties, 'roles', id_key='name', split_char=',')
        else:
            roles = []
            for p in properties:
                if p.startswith("roles_"):
                    if properties.get(p, False):
                        roles.append(p[6:])
            return roles

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

    def check_permissions(self, user, node, is_admin, is_local_admin):

        if node is None:
            return False

        # an ADMIN is always authorized
        if is_admin:
            return True

        # You are neither an ADMIN nor a LOCAL ADMIN
        if not is_local_admin:
            return False

        # If you are not an ADMIN, you cannot modify yourself...
        # use the profile instead!
        if user == node:
            return False

        # If you are not an ADMIN, you cannot modify ADMINs
        if self.auth.role_admin in self.auth.get_roles_from_user(node):
            return False

        # FIXME: only implemented for neo4j
        # You are a local admin... but the group matches??
        for g in user.coordinator.all():
            if node.belongs_to.is_connected(g):
                return True

        # FIXME: only implemented for neo4j
        # All local admins have rights on general users
        # g = general group
        g = self.graph.Group.nodes.get_or_none(shortname="default")
        if g is not None:
            if node.belongs_to.is_connected(g):
                return True

        return False

    def send_notification(self, user, unhashed_password, is_update=False):

        title = mem.customizer._configurations \
            .get('project', {}) \
            .get('title', "Unkown title")

        subject = "%s: " % title
        if is_update:
            subject += "password changed"
            template = "update_credentials.html"
        else:
            subject += "new credentials"
            template = "new_credentials.html"

        replaces = {
            "username": user.email,
            "password": unhashed_password
        }

        html = get_html_template(template, replaces)

        body = """
            Username: %s"
            Password: %s"
        """ % (user.email, unhashed_password)

        if html is None:
            send_mail(body, subject, user.email)
        else:
            send_mail(html, subject, user.email, plain_body=body)

    @decorate.catch_error()
    @catch_graph_exceptions
    def get(self, id=None):

        data = []
        if not detector.check_availability('neo4j'):
            log.warning("This endpoint is implemented only for neo4j")
            return self.force_response(data)

        self.graph = self.get_service_instance('neo4j')

        is_admin = self.auth.verify_admin()
        is_local_admin = self.auth.verify_local_admin()
        if not is_admin and not is_local_admin:
            raise RestApiException(
                "You are not authorized: missing privileges",
                status_code=hcodes.HTTP_BAD_UNAUTHORIZED)

        current_user = self.get_current_user()
        nodeset = self.graph.User.nodes

        for n in nodeset.all():

            is_authorized = self.check_permissions(
                current_user, n, is_admin, is_local_admin
            )
            if not is_authorized:
                continue

            user = self.getJsonResponse(n, max_relationship_depth=1)
            data.append(user)

        return self.force_response(data)

    @decorate.catch_error()
    @catch_graph_exceptions
    @graph_transactions
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
        is_local_admin = self.auth.verify_local_admin()
        if not is_admin and not is_local_admin:
            raise RestApiException(
                "You are not authorized: missing privileges",
                status_code=hcodes.HTTP_BAD_UNAUTHORIZED)

        schema = self.get_endpoint_custom_definition()

        if 'get_schema' in v:

            new_schema = schema[:]

            if send_mail_is_active():
                new_schema.append(
                    {
                        "name": "email_notification",
                        "description": "Notify password by email",
                        "type": "boolean",
                        "default": False,
                        "custom": {
                            "htmltype": "checkbox",
                            "label": "Notify password by email"
                        }
                    }
                )

            if 'autocomplete' in v and not v['autocomplete']:
                for idx, val in enumerate(new_schema):
                    if val["name"] == "group":
                        new_schema[idx]["default"] = None

                        if "custom" not in new_schema[idx]:
                            new_schema[idx]["custom"] = {}

                        new_schema[idx]["custom"]["htmltype"]: "select"
                        new_schema[idx]["custom"]["label"]: "Group"

                        new_schema[idx]["enum"] = []

                        for g in self.graph.Group.nodes.all():
                            new_schema[idx]["enum"].append(
                                {g.uuid: g.fullname}
                            )
                            if new_schema[idx]["default"] is None:
                                new_schema[idx]["default"] = g.uuid

                    # Roles as multi checkbox
                    if val["name"] == "roles":

                        cypher = "MATCH (r:Role)"
                        if not self.auth.verify_admin():
                            allowed_roles = mem.customizer._configurations \
                                .get('variables', {}) \
                                .get('backend', {}) \
                                .get('allowed_roles', [])
                            cypher += " WHERE r.name in %s" % allowed_roles
                        # Admin only
                        else:
                            cypher += " WHERE r.description <> 'automatic'"

                        cypher += " RETURN r ORDER BY r.name ASC"

                        result = self.graph.cypher(cypher)

                        del new_schema[idx]

                        for row in result:
                            r = self.graph.Role.inflate(row[0])

                            role = {
                                "type": "checkbox",
                                # "name": "roles[%s]" % r.name,
                                "name": "roles_%s" % r.name,
                                # "name": r.name,
                                "custom": {
                                    "label": r.description
                                }
                            }

                            new_schema.insert(idx, role)

            if is_admin:
                return self.force_response(new_schema)

            # institutes = self.graph.Institute.nodes
            # users = self.graph.User.nodes
            current_user = self.get_current_user()
            for idx, val in enumerate(new_schema):
                if val["name"] == "group":
                    new_schema[idx]["default"] = None
                    new_schema[idx]["custom"] = {
                        "htmltype": "select",
                        "label": "Group"
                    }
                    new_schema[idx]["enum"] = []

                    default_group = self.graph.Group.nodes.get_or_none(
                        shortname="default")

                    if default_group is not None:
                        new_schema[idx]["enum"].append(
                            {default_group.uuid: default_group.shortname}
                        )
                        new_schema[idx]["default"] = default_group.uuid

                    for g in current_user.coordinator.all():

                        if g == default_group:
                            continue

                        new_schema[idx]["enum"].append(
                            {g.uuid: g.shortname}
                        )
                        if new_schema[idx]["default"] is None:
                            new_schema[idx]["default"] = g.uuid

            return self.force_response(new_schema)

        # INIT #
        properties = self.read_properties(schema, v)

        roles = self.parse_roles(v)
        if not is_admin:
            allowed_roles = mem.customizer._configurations \
                .get('variables', {}) \
                .get('backend', {}) \
                .get('allowed_roles', [])

            for r in roles:
                if r not in allowed_roles:
                    raise RestApiException(
                        "You are allowed to assign users to this role")

        if "password" in properties and properties["password"] == "":
            del properties["password"]

        if "password" in properties:
            unhashed_password = properties["password"]
        else:
            unhashed_password = None

        user = self.auth.create_user(properties, roles)

        group = None
        if 'group' in v:
            group = self.parse_group(v)

        if group is not None:
            if not is_admin:
                current_user = self.get_current_user()
                if not group.coordinator.is_connected(current_user):
                    raise RestApiException(
                        "You are allowed to assign users to this group")

            user.belongs_to.connect(group)

        email_notification = v.get('email_notification', False)
        if email_notification and unhashed_password is not None:
            self.send_notification(user, unhashed_password, is_update=False)

        return self.force_response(user.uuid)

    @decorate.catch_error()
    @catch_graph_exceptions
    @graph_transactions
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
        is_local_admin = self.auth.verify_local_admin()
        if not is_admin and not is_local_admin:
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
            current_user, user, is_admin, is_local_admin
        )
        if not is_authorized:
            raise RestApiException(
                "This user cannot be found or you are not authorized")

        if "password" in v and v["password"] == "":
            del v["password"]

        if "password" in v:
            unhashed_password = v["password"]
            v["password"] = BaseAuthentication.hash_password(v["password"])
        else:
            unhashed_password = None

        if "email" in v:
            v["email"] = v["email"].lower()

        self.update_properties(user, schema, v)
        user.save()

        if 'group' in v:

            group = self.parse_group(v)

            if not is_admin:
                if not group.coordinator.is_connected(current_user):
                    raise RestApiException(
                        "You are allowed to assign users to this group")

            p = None
            for p in user.belongs_to.all():
                if p == group:
                    continue

            if p is not None:
                user.belongs_to.reconnect(p, group)
            else:
                user.belongs_to.connect(group)

        roles = self.parse_roles(v)
        if not is_admin:
            allowed_roles = mem.customizer._configurations \
                .get('variables', {}) \
                .get('backend', {}) \
                .get('allowed_roles', [])

            for r in roles:
                if r not in allowed_roles:
                    raise RestApiException(
                        "You are allowed to assign users to this role")

        self.auth.link_roles(user, roles)

        email_notification = v.get('email_notification', False)
        if email_notification and unhashed_password is not None:
            self.send_notification(user, unhashed_password, is_update=True)

        return self.empty_response()

    @decorate.catch_error()
    @catch_graph_exceptions
    @graph_transactions
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
        is_local_admin = self.auth.verify_local_admin()
        if not is_admin and not is_local_admin:
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
            current_user, user, is_admin, is_local_admin
        )
        if not is_authorized:
            raise RestApiException(
                "This user cannot be found or you are not authorized")

        user.delete()

        return self.empty_response()


class UserRole(GraphBaseOperations):
    @decorate.catch_error(exception=Exception, catch_generic=True)
    @catch_graph_exceptions
    def get(self, query=None):

        self.graph = self.get_service_instance('neo4j')

        data = []

        cypher = "MATCH (r:Role)"
        if not self.auth.verify_admin():
            allowed_roles = mem.customizer._configurations \
                .get('variables', {}) \
                .get('backend', {}) \
                .get('allowed_roles', [])
            # cypher += " WHERE r.name = 'Archive' or r.name = 'Researcher'"
            cypher += " WHERE r.name in %s" % allowed_roles
        # Admin only
        elif query is not None:
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
