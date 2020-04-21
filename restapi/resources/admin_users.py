# -*- coding: utf-8 -*-

import re
from sqlalchemy.exc import IntegrityError

from restapi import decorators
from restapi.rest.definition import EndpointResource
from restapi.exceptions import RestApiException
from restapi.confs import get_project_configuration
from restapi.services.authentication import BaseAuthentication
from restapi.services.detect import detector
from restapi.services.mail import send_mail, send_mail_is_active
from restapi.utilities.templates import get_html_template

from restapi.utilities.logs import log


class AdminUsers(EndpointResource):

    auth_service = detector.authentication_service
    neo4j_enabled = auth_service == 'neo4j'
    sql_enabled = auth_service == 'sqlalchemy'
    mongo_enabled = auth_service == 'mongo'

    depends_on = ["not ADMINER_DISABLED"]
    labels = ["admin"]

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
                "200": {"description": "The uuid of the new user is returned"},
                "409": {"description": "This user already exists"},
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
                'Group not found', status_code=400
            )

        group_id = groups.pop()
        group = self.graph.Group.nodes.get_or_none(uuid=group_id)

        if group is None:
            raise RestApiException(
                'Group not found', status_code=400
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

    @decorators.catch_errors()
    @decorators.auth.required()
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
                status_code=401,
            )

        users = self.auth.get_users(user_id)
        if users is None:
            raise RestApiException(
                "This user cannot be found or you are not authorized"
            )
        if self.neo4j_enabled:
            self.graph = self.get_service_instance('neo4j')

        current_user = self.get_current_user()
        for user in users:

            is_authorized = self.check_permissions(
                current_user, user, is_admin, is_local_admin
            )
            if not is_authorized:
                continue

            user_data = {
                "id": user.uuid,
                "email": user.email,
                "name": user.name,
                "surname": user.surname,
                "first_login": user.first_login,
                "last_login": user.last_login,
                "last_password_change": user.last_password_change,
                "is_active": user.is_active,
                "privacy_accepted": user.privacy_accepted,
                "_roles": []
            }
            for role in user.roles:
                user_data["_roles"].append(
                    {
                        # "id": role.id,
                        "name": role.name,
                        "description": role.description,
                    }
                )

            data.append(user_data)

        return self.response(data)

    @decorators.catch_errors()
    @decorators.auth.required()
    def post(self):

        v = self.get_input()
        if len(v) == 0:
            raise RestApiException('Empty input', status_code=400)

        if self.neo4j_enabled:
            self.graph = self.get_service_instance('neo4j')

        is_admin = self.auth.verify_admin()
        is_local_admin = self.auth.verify_local_admin()
        if not is_admin and not is_local_admin:
            raise RestApiException(
                "You are not authorized: missing privileges",
                status_code=401,
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
                return self.response(new_schema)

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

            return self.response(new_schema)

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

            # Message is produced by authentication/neo4j.py and authentication/mongo.py
            message = str(e).split('\n')
            if not re.search(r"Can't create user .*", message[0]):
                log.error("Unrecognized error message: {}", e)
                raise e

            # ~ duplicated int decorators

            # Neo4j
            m = re.search(
                r"Node\([0-9]+\) already exists with label `(.+)` and property `(.+)` = '(.+)'",
                message[1]
            )

            # Mongodb
            if not m:
                m = re.search(
                    r".+ duplicate key error collection: auth\.(.+) index: .+ dup key: { (.+): \"(.+)\" }",
                    message[1]
                )
            if m:
                node = m.group(1)
                prop = m.group(2)
                val = m.group(3)
                error = "A {} already exists with {}: {}".format(node, prop, val)
                raise RestApiException(error, status_code=409)
            else:
                raise e

        if self.sql_enabled:

            try:
                self.auth.db.session.commit()
            except IntegrityError:
                self.auth.db.session.rollback()
                raise RestApiException(
                    "This user already exists", status_code=409)

        # If created by admins users must accept privacy at first login
        if not v.get("privacy_accepted", True):
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

        return self.response(user.uuid)

    @decorators.catch_errors()
    @decorators.auth.required()
    def put(self, user_id):

        schema = self.get_endpoint_custom_definition()
        if self.neo4j_enabled:
            self.graph = self.get_service_instance('neo4j')

        is_admin = self.auth.verify_admin()
        is_local_admin = self.auth.verify_local_admin()
        if not is_admin and not is_local_admin:
            raise RestApiException(
                "You are not authorized: missing privileges",
                status_code=401,
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

    @decorators.catch_errors()
    @decorators.auth.required()
    def delete(self, user_id):

        if self.neo4j_enabled:
            self.graph = self.get_service_instance('neo4j')

        is_admin = self.auth.verify_admin()
        is_local_admin = self.auth.verify_local_admin()
        if not is_admin and not is_local_admin:
            raise RestApiException(
                "You are not authorized: missing privileges",
                status_code=401,
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
