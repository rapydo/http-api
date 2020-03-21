# -*- coding: utf-8 -*-

import re
from sqlalchemy.exc import IntegrityError

from restapi import decorators as decorate
from restapi.protocols.bearer import authentication
from restapi.rest.definition import EndpointResource
from restapi.exceptions import RestApiException
from restapi.confs import get_project_configuration
from restapi.services.authentication import BaseAuthentication
from restapi.services.detect import detector
from restapi.services.mail import send_mail, send_mail_is_active
from restapi.utilities.templates import get_html_template
from restapi.utilities.htmlcodes import hcodes

# from restapi.utilities.logs import log


class AdminUsers(EndpointResource):

    auth_service = detector.authentication_service
    neo4j_enabled = auth_service == 'neo4j'
    sql_enabled = auth_service == 'sqlalchemy'
    mongo_enabled = auth_service == 'mongo'

    depends_on = ["not ADMINER_DISABLED"]
    labels = ["admin"]
    # expose_schema = True

    GET = {
        "/admin/users": {
            "summary": "List of users",
            "responses": {
                "200": {"description": "List of users successfully retrieved"}
            },
        },
        "/admin/users/<user_id>": {
            "summary": "Obtain information on a single user",
            "responses": {
                "200": {"description": "User information successfully retrieved"}
            },
        },
    }
    POST = {
        "/admin/users": {
            "summary": "Create a new user",
            "custom_parameters": ["AdminUsers"],
            "responses": {
                "200": {"description": "The uuid of the new user is returned"}
            },
        }
    }
    PUT = {
        "/admin/users/<user_id>": {
            "summary": "Modify a user",
            "custom_parameters": ["AdminUsers"],
            "responses": {"200": {"description": "User successfully modified"}},
        }
    }
    DELETE = {
        "/admin/users/<user_id>": {
            "summary": "Delete a user",
            "responses": {"200": {"description": "User successfully deleted"}},
        }
    }

    def parse_roles(self, properties):

        if 'roles' in properties:
            return self.parseAutocomplete(
                properties, 'roles', id_key='name', split_char=','
            )
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
                'Group not found', status_code=hcodes.HTTP_BAD_REQUEST
            )

        group_id = groups.pop()
        group = self.graph.Group.nodes.get_or_none(uuid=group_id)

        if group is None:
            raise RestApiException(
                'Group not found', status_code=hcodes.HTTP_BAD_REQUEST
            )

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

        # FIXME: groups management is only implemented for neo4j
        if self.neo4j_enabled:
            # You are a local admin... but the group matches??
            for g in user.coordinator.all():
                if node.belongs_to.is_connected(g):
                    return True

            # All local admins have rights on general users
            g = self.graph.Group.nodes.get_or_none(shortname="default")
            if g is not None:
                if node.belongs_to.is_connected(g):
                    return True

        return False

    def send_notification(self, user, unhashed_password, is_update=False):

        title = get_project_configuration(
            "project.title", default='Unkown title'
        )

        if is_update:
            subject = "{}: password changed".format(title)
            template = "update_credentials.html"
        else:
            subject = "{}: new credentials".format(title)
            template = "new_credentials.html"

        replaces = {"username": user.email, "password": unhashed_password}

        html = get_html_template(template, replaces)

        body = """
Username: "{}"
Password: "{}"
        """.format(
            user.email,
            unhashed_password,
        )

        if html is None:
            send_mail(body, subject, user.email)
        else:
            send_mail(html, subject, user.email, plain_body=body)

    @decorate.catch_error()
    @authentication.required()
    def get(self, user_id=None):

        data = []

        is_admin = self.auth.verify_admin()
        is_local_admin = self.auth.verify_local_admin()
        if not is_admin and not is_local_admin:
            extra_debug = "is_admin = {};".format(is_admin)
            extra_debug += " is_local_admin = {};".format(is_local_admin)
            extra_debug += " roles = {};".format(self.auth.get_roles_from_user())
            raise RestApiException(
                "You are not authorized: missing privileges. {}".format(extra_debug),
                status_code=hcodes.HTTP_BAD_UNAUTHORIZED,
            )

        users = self.auth.get_users(user_id)
        if users is None:
            raise RestApiException(
                "This user cannot be found or you are not authorized"
            )
        if self.neo4j_enabled:
            self.graph = self.get_service_instance('neo4j')

        current_user = self.get_current_user()
        for u in users:

            is_authorized = self.check_permissions(
                current_user, u, is_admin, is_local_admin
            )
            if not is_authorized:
                continue

            if self.neo4j_enabled:
                user = self.getJsonResponse(u, max_relationship_depth=1)
            elif self.sql_enabled:
                user = self.getJsonResponseFromSql(u)
                user['relationships'] = {}
                user['relationships']['roles'] = []
                for role in u.roles:
                    r = self.getJsonResponseFromSql(role)
                    user['relationships']['roles'].append(r)
            elif self.mongo_enabled:
                user = self.getJsonResponseFromMongo(u)
                user['relationships'] = {}
                user['relationships']['roles'] = self.auth.get_roles_from_user(u)
            else:
                raise RestApiException(
                    "Invalid auth backend, all known db are disabled"
                )

            data.append(user)

        return self.force_response(data)

    @decorate.catch_error()
    @authentication.required()
    def post(self):

        v = self.get_input()
        if len(v) == 0:
            raise RestApiException('Empty input', status_code=hcodes.HTTP_BAD_REQUEST)

        if self.neo4j_enabled:
            self.graph = self.get_service_instance('neo4j')

        is_admin = self.auth.verify_admin()
        is_local_admin = self.auth.verify_local_admin()
        if not is_admin and not is_local_admin:
            raise RestApiException(
                "You are not authorized: missing privileges",
                status_code=hcodes.HTTP_BAD_UNAUTHORIZED,
            )

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
                            "label": "Notify password by email",
                        },
                    }
                )

            if 'autocomplete' in v and not v['autocomplete']:
                for idx, val in enumerate(new_schema):
                    # FIXME: groups management is only implemented for neo4j
                    if val["name"] == "group":
                        new_schema[idx]["default"] = None

                        if "custom" not in new_schema[idx]:
                            new_schema[idx]["custom"] = {}

                        new_schema[idx]["custom"]["htmltype"] = "select"
                        new_schema[idx]["custom"]["label"] = "Group"
                        new_schema[idx]["enum"] = []

                        for g in self.graph.Group.nodes.all():
                            group_name = "{} - {}".format(g.shortname, g.fullname)
                            new_schema[idx]["enum"].append({g.uuid: group_name})
                            if new_schema[idx]["default"] is None:
                                new_schema[idx]["default"] = g.uuid

                    # Roles as multi checkbox
                    if val["name"] == "roles":

                        roles = self.auth.get_roles()
                        is_admin = self.auth.verify_admin()
                        allowed_roles = get_project_configuration(
                            "variables.backend.allowed_roles",
                            default=[],
                        )
                        del new_schema[idx]

                        for r in roles:

                            if is_admin:
                                if r.description == 'automatic':
                                    continue
                            else:
                                if r.name not in allowed_roles:
                                    continue

                            role = {
                                "type": "checkbox",
                                "name": "roles_{}".format(r.name),
                                "custom": {"label": r.description},
                            }

                            new_schema.insert(idx, role)

            if is_admin:
                return self.force_response(new_schema)

            current_user = self.get_current_user()
            for idx, val in enumerate(new_schema):
                # FIXME: groups management is only implemented for neo4j
                if val["name"] == "group":
                    new_schema[idx]["default"] = None
                    if "custom" not in new_schema[idx]:
                        new_schema[idx]["custom"] = {}

                    new_schema[idx]["custom"]["htmltype"] = "select"
                    new_schema[idx]["custom"]["label"] = "Group"
                    new_schema[idx]["enum"] = []

                    default_group = self.graph.Group.nodes.get_or_none(
                        shortname="default"
                    )

                    defg = None
                    if default_group is not None:
                        new_schema[idx]["enum"].append(
                            {default_group.uuid: default_group.shortname}
                        )
                        # new_schema[idx]["default"] = default_group.uuid
                        defg = default_group.uuid

                    for g in current_user.coordinator.all():

                        if g == default_group:
                            continue

                        group_name = "{} - {}".format(g.shortname, g.fullname)
                        new_schema[idx]["enum"].append({g.uuid: group_name})
                        if defg is None:
                            defg = g.uuid
                        # if new_schema[idx]["default"] is None:
                        #     new_schema[idx]["default"] = g.uuid
                    if (len(new_schema[idx]["enum"])) == 1:
                        new_schema[idx]["default"] = defg

            return self.force_response(new_schema)

        # INIT #
        properties = self.read_properties(schema, v)

        roles = self.parse_roles(v)
        if not is_admin:
            allowed_roles = get_project_configuration(
                "variables.backend.allowed_roles",
                default=[],
            )

            for r in roles:
                if r not in allowed_roles:
                    raise RestApiException(
                        "You are not allowed to assign users to this role"
                    )

        if "password" in properties and properties["password"] == "":
            del properties["password"]

        if "password" in properties:
            unhashed_password = properties["password"]
        else:
            unhashed_password = None

        try:
            user = self.auth.create_user(properties, roles)
        except AttributeError as e:

            # Duplicated from decorators
            prefix = "Can't create user .*:\nNode\([0-9]+\) already exists with label"
            m = re.search("{} `(.+)` and property `(.+)` = '(.+)'".format(prefix), str(e))

            if m:
                node = m.group(1)
                prop = m.group(2)
                val = m.group(3)
                error = "A {} already exists with {} = {}".format(node, prop, val)
                raise RestApiException(error, status_code=hcodes.HTTP_BAD_CONFLICT)
            else:
                raise e

        if self.sql_enabled:

            try:
                self.auth.db.session.commit()
            except IntegrityError:
                self.auth.db.session.rollback()
                raise RestApiException("This user already exists")

        # If created by admins, credentials
        # must accept privacy at the login
        if "privacy_accepted" in v:
            if not v["privacy_accepted"]:
                if hasattr(user, 'privacy_accepted'):
                    user.privacy_accepted = False
                    self.auth.save_user(user)

        # FIXME: groups management is only implemented for neo4j
        group = None
        if 'group' in v:
            group = self.parse_group(v)

        if group is not None:
            if not is_admin and group.shortname != "default":
                current_user = self.get_current_user()
                if not group.coordinator.is_connected(current_user):
                    raise RestApiException(
                        "You are not allowed to assign users to this group"
                    )

            user.belongs_to.connect(group)

        email_notification = v.get('email_notification', False)
        if email_notification and unhashed_password is not None:
            self.send_notification(user, unhashed_password, is_update=False)

        return self.force_response(user.uuid)

    @decorate.catch_error()
    @authentication.required()
    def put(self, user_id=None):

        if user_id is None:

            raise RestApiException(
                "Please specify a user id", status_code=hcodes.HTTP_BAD_REQUEST
            )

        schema = self.get_endpoint_custom_definition()
        if self.neo4j_enabled:
            self.graph = self.get_service_instance('neo4j')

        is_admin = self.auth.verify_admin()
        is_local_admin = self.auth.verify_local_admin()
        if not is_admin and not is_local_admin:
            raise RestApiException(
                "You are not authorized: missing privileges",
                status_code=hcodes.HTTP_BAD_UNAUTHORIZED,
            )

        v = self.get_input()

        user = self.auth.get_users(user_id)

        if user is None:
            raise RestApiException(
                "This user cannot be found or you are not authorized"
            )

        user = user[0]

        current_user = self.get_current_user()
        is_authorized = self.check_permissions(
            current_user, user, is_admin, is_local_admin
        )
        if not is_authorized:
            raise RestApiException(
                "This user cannot be found or you are not authorized"
            )

        if "password" in v and v["password"] == "":
            del v["password"]

        if "password" in v:
            unhashed_password = v["password"]
            v["password"] = BaseAuthentication.get_password_hash(v["password"])
        else:
            unhashed_password = None

        if "email" in v:
            v["email"] = v["email"].lower()

        roles = self.parse_roles(v)
        if not is_admin:
            allowed_roles = get_project_configuration(
                "variables.backend.allowed_roles",
                default=[],
            )

            for r in roles:
                if r not in allowed_roles:
                    raise RestApiException(
                        "You are not allowed to assign users to this role"
                    )

        self.auth.link_roles(user, roles)
        # Cannot update email address (unique username used to login-in)
        v.pop('email', None)

        if self.neo4j_enabled:
            self.update_properties(user, schema, v)
        elif self.sql_enabled:
            self.update_sql_properties(user, schema, v)
        elif self.mongo_enabled:
            self.update_mongo_properties(user, schema, v)
        else:
            raise RestApiException("Invalid auth backend, all known db are disabled")

        self.auth.save_user(user)

        # FIXME: groups management is only implemented for neo4j
        if 'group' in v:

            group = self.parse_group(v)

            if not is_admin and group.shortname != "default":
                if not group.coordinator.is_connected(current_user):
                    raise RestApiException(
                        "You are not allowed to assign users to this group"
                    )

            p = None
            for p in user.belongs_to.all():
                if p == group:
                    continue

            if p is not None:
                user.belongs_to.reconnect(p, group)
            else:
                user.belongs_to.connect(group)

        email_notification = v.get('email_notification', False)
        if email_notification and unhashed_password is not None:
            self.send_notification(user, unhashed_password, is_update=True)

        return self.empty_response()

    @decorate.catch_error()
    @authentication.required()
    def delete(self, user_id=None):

        if user_id is None:

            raise RestApiException(
                "Please specify a user id", status_code=hcodes.HTTP_BAD_REQUEST
            )

        if self.neo4j_enabled:
            self.graph = self.get_service_instance('neo4j')

        is_admin = self.auth.verify_admin()
        is_local_admin = self.auth.verify_local_admin()
        if not is_admin and not is_local_admin:
            raise RestApiException(
                "You are not authorized: missing privileges",
                status_code=hcodes.HTTP_BAD_UNAUTHORIZED,
            )

        user = self.auth.get_users(user_id)

        if user is None:
            raise RestApiException(
                "This user cannot be found or you are not authorized"
            )

        user = user[0]

        current_user = self.get_current_user()
        is_authorized = self.check_permissions(
            current_user, user, is_admin, is_local_admin
        )
        if not is_authorized:
            raise RestApiException(
                "This user cannot be found or you are not authorized"
            )

        if self.neo4j_enabled:
            user.delete()
        elif self.sql_enabled:
            self.auth.db.session.delete(user)
            self.auth.db.session.commit()
        elif self.mongo_enabled:
            user.delete()
        else:
            raise RestApiException("Invalid auth backend, all known db are disabled")

        return self.empty_response()


class UserRole(EndpointResource):

    depends_on = ["not ADMINER_DISABLED"]
    labels = ["miscellaneous"]
    # expose_schema = True

    GET = {
        "/role": {
            "summary": "List of existing roles",
            "responses": {
                "200": {"description": "List of roles successfully retrieved"}
            },
        },
        "/role/<query>": {
            "summary": "List of existing roles matching a substring query",
            "responses": {
                "200": {"description": "Matching roles successfully retrieved"}
            },
        },
    }

    @decorate.catch_error(exception=Exception, catch_generic=True)
    @authentication.required()
    def get(self, query=None):

        if self.neo4j_enabled:
            self.graph = self.get_service_instance('neo4j')

        data = []

        cypher = "MATCH (r:Role)"
        if not self.auth.verify_admin():
            allowed_roles = get_project_configuration(
                "variables.backend.allowed_roles",
                default=[],
            )
            # cypher += " WHERE r.name = 'Archive' or r.name = 'Researcher'"
            cypher += " WHERE r.name in {}".format(allowed_roles)
        # Admin only
        elif query is not None:
            cypher += " WHERE r.description <> 'automatic'"
            cypher += " AND r.name =~ '(?i).*{}.*'".format(query)

        cypher += " RETURN r ORDER BY r.name ASC"

        if query is None:
            cypher += " LIMIT 20"

        result = self.graph.cypher(cypher)
        for row in result:
            r = self.graph.Role.inflate(row[0])
            data.append({"name": r.name, "description": r.description})

        return self.force_response(data)
