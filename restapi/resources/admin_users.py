# -*- coding: utf-8 -*-

import re
from collections import OrderedDict
from sqlalchemy.exc import IntegrityError
from flask_apispec import MethodResource
from flask_apispec import marshal_with
from flask_apispec import use_kwargs
from marshmallow import fields, validate
from restapi.models import Schema

from restapi import decorators
from restapi.rest.definition import EndpointResource
from restapi.exceptions import RestApiException
from restapi.confs import get_project_configuration
from restapi.services.authentication import BaseAuthentication
from restapi.services.detect import detector
from restapi.utilities.meta import Meta
from restapi.services.mail import send_mail, send_mail_is_active
from restapi.utilities.templates import get_html_template

from restapi.utilities.logs import log


def send_notification(user, unhashed_password, is_update=False):

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


def parseAutocomplete(properties, key, id_key='value', split_char=None):
    value = properties.get(key, None)

    ids = []

    if value is None:
        return ids

    # Multiple autocomplete
    if isinstance(value, list):
        for v in value:
            if v is None:
                return None
            if id_key in v:
                ids.append(v[id_key])
            else:
                ids.append(v)
        return ids

    # Single autocomplete
    if id_key in value:
        return [value[id_key]]

    # Command line input
    if split_char is None:
        return [value]

    return value.split(split_char)


def parse_roles(properties):

    keys = []
    roles = []
    for p in properties:
        if p.startswith("roles_"):
            keys.append(p)
            if properties.get(p, False):
                roles.append(p[6:])
    return roles, keys


def parse_group(v, neo4j):
    groups = parseAutocomplete(v, 'group', id_key='id')

    if groups is None:
        raise RestApiException(
            'Group not found', status_code=400
        )

    group_id = groups.pop()
    group = neo4j.Group.nodes.get_or_none(uuid=group_id)

    if group is None:
        raise RestApiException(
            'Group not found', status_code=400
        )

    return group


def get_roles(auth):

    roles = {}
    for r in auth.get_roles():

        if r.description == 'automatic':
            continue

        roles["roles_{}".format(r.name)] = r.description

    return roles


def get_groups():
    auth_service = detector.authentication_service

    if auth_service == 'neo4j':

        groups = {}
        neo4j = detector.get_service_instance('neo4j')
        for g in neo4j.Group.nodes.all():
            group_name = "{} - {}".format(g.shortname, g.fullname)
            groups[g.uuid] = group_name

        return groups

    if auth_service == 'sqlalchemy':
        return None

    if auth_service == 'mongo':
        return None

    log.error("Unknown auth service: {}", auth_service)


class Role(Schema):

    name = fields.Str()
    description = fields.Str()


class Group(Schema):
    uuid = fields.Str()
    fullname = fields.Str()
    shortname = fields.Str()


def get_output_schema():
    attributes = OrderedDict()

    attributes['uuid'] = fields.Str()
    attributes['email'] = fields.Email()
    attributes['name'] = fields.Str()
    attributes['surname'] = fields.Str()
    attributes['first_login'] = fields.DateTime()
    attributes['last_login'] = fields.DateTime()
    attributes['last_password_change'] = fields.DateTime()
    attributes['is_active'] = fields.Boolean()
    attributes['privacy_accepted'] = fields.Boolean()
    attributes['roles'] = fields.List(fields.Nested(Role))

    attributes['belongs_to'] = fields.List(fields.Nested(Group), data_key='group')

    obj = Meta.get_customizer_class('apis.profile', 'CustomProfile')
    if obj is not None and hasattr(obj, "get_custom_fields"):
        try:
            custom_fields = obj.get_custom_fields()
            if custom_fields:
                attributes.update(custom_fields)
        except BaseException as e:
            log.error("Could not retrieve custom profile fields:\n{}", e)

    schema = Schema.from_dict(attributes)
    return schema(many=True)


def get_input_schema(set_required=True, exclude_email=False):

    auth = EndpointResource.load_authentication()

    attributes = OrderedDict()
    if not exclude_email:
        attributes["email"] = fields.Email(required=set_required)
    attributes["password"] = fields.Str(
        required=set_required,
        password=True,
        validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH)
    )
    attributes["name"] = fields.Str(
        required=set_required, validate=validate.Length(min=1))
    attributes["surname"] = fields.Str(
        required=set_required, validate=validate.Length(min=1))

    for key, label in get_roles(auth).items():
        attributes[key] = fields.Bool(label=label)

    groups = get_groups()
    if groups:
        attributes["group"] = fields.Str(
            required=True,
            validate=validate.OneOf(
                choices=groups.keys(),
                labels=groups.values()
            )
        )

    obj = Meta.get_customizer_class('apis.profile', 'CustomProfile')
    if obj is not None and hasattr(obj, "get_custom_fields"):
        try:
            custom_fields = obj.get_custom_fields()
            if custom_fields:
                attributes.update(custom_fields)
        except BaseException as e:
            log.error("Could not retrieve custom profile fields:\n{}", e)

    if send_mail_is_active():
        attributes["email_notification"] = fields.Bool(
            label="Notify password by email"
        )

    return Schema.from_dict(attributes)


class AdminUsers(MethodResource, EndpointResource):

    auth_service = detector.authentication_service
    neo4j_enabled = auth_service == 'neo4j'
    sql_enabled = auth_service == 'sqlalchemy'
    mongo_enabled = auth_service == 'mongo'

    depends_on = ["not ADMINER_DISABLED"]
    labels = ["admin"]

    _GET = {
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
    _POST = {
        "/admin/users": {
            "summary": "Create a new user",
            "responses": {
                "200": {"description": "The uuid of the new user is returned"},
                "409": {"description": "This user already exists"},
            },
        }
    }
    _PUT = {
        "/admin/users/<user_id>": {
            "summary": "Modify a user",
            "responses": {"200": {"description": "User successfully modified"}},
        }
    }
    _DELETE = {
        "/admin/users/<user_id>": {
            "summary": "Delete a user",
            "responses": {"200": {"description": "User successfully deleted"}},
        }
    }

    @decorators.catch_errors()
    @decorators.auth.required(roles=['admin_root'])
    @marshal_with(get_output_schema(), code=200)
    def get(self, user_id=None):

        users = self.auth.get_users(user_id)
        if users is None:
            raise RestApiException(
                "This user cannot be found or you are not authorized"
            )

        return self.response(users)

    @decorators.catch_errors()
    @decorators.auth.required(roles=['admin_root'])
    @use_kwargs(get_input_schema())
    def post(self, **kwargs):

        roles, roles_keys = parse_roles(kwargs)
        for r in roles_keys:
            kwargs.pop(r)

        unhashed_password = kwargs["password"]

        # If created by admins users must accept privacy at first login
        kwargs['privacy_accepted'] = False

        try:
            user = self.auth.create_user(kwargs, roles)
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

        # FIXME: groups management is only implemented for neo4j
        if 'group' in kwargs:

            if self.neo4j_enabled:
                self.graph = self.get_service_instance('neo4j')
            group = parse_group(kwargs, self.graph)

            if group is not None:
                user.belongs_to.connect(group)

        email_notification = kwargs.get('email_notification', False)
        if email_notification and unhashed_password is not None:
            send_notification(user, unhashed_password, is_update=False)

        return self.response(user.uuid)

    @decorators.catch_errors()
    @decorators.auth.required(roles=['admin_root'])
    @use_kwargs(get_input_schema(set_required=False, exclude_email=True))
    def put(self, user_id, **kwargs):

        # log.critical(kwargs)

        user = self.auth.get_users(user_id)

        if user is None:
            raise RestApiException(
                "This user cannot be found or you are not authorized"
            )

        user = user[0]

        if "password" in kwargs and kwargs["password"] == "":
            del kwargs["password"]

        if "password" in kwargs:
            unhashed_password = kwargs["password"]
            kwargs["password"] = BaseAuthentication.get_password_hash(
                kwargs["password"]
            )
        else:
            unhashed_password = None

        roles, roles_keys = parse_roles(kwargs)
        for r in roles_keys:
            kwargs.pop(r)

        self.auth.link_roles(user, roles)
        # Cannot update email address (unique username used to login-in)
        kwargs.pop('email', None)

        if self.neo4j_enabled:
            self.graph = self.get_service_instance('neo4j')
            self.update_properties(user, kwargs, kwargs)
        elif self.sql_enabled:
            self.update_sql_properties(user, kwargs, kwargs)
        elif self.mongo_enabled:
            self.update_mongo_properties(user, kwargs, kwargs)
        else:
            raise RestApiException("Invalid auth backend, all known db are disabled")

        self.auth.save_user(user)

        # FIXME: groups management is only implemented for neo4j
        if 'group' in kwargs:

            group = parse_group(kwargs, self.graph)

            p = None
            for p in user.belongs_to.all():
                if p == group:
                    continue

            if p is not None:
                user.belongs_to.reconnect(p, group)
            else:
                user.belongs_to.connect(group)

        email_notification = kwargs.get('email_notification', False)
        if email_notification and unhashed_password is not None:
            send_notification(user, unhashed_password, is_update=True)

        return self.empty_response()

    @decorators.catch_errors()
    @decorators.auth.required(roles=['admin_root'])
    def delete(self, user_id):

        user = self.auth.get_users(user_id)

        if user is None:
            raise RestApiException(
                "This user cannot be found or you are not authorized"
            )

        user = user[0]

        if self.neo4j_enabled or self.mongo_enabled:
            user.delete()
        elif self.sql_enabled:
            self.auth.db.session.delete(user)
            self.auth.db.session.commit()
        else:
            raise RestApiException("Invalid auth backend, all known db are disabled")

        return self.empty_response()
