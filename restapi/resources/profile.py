# -*- coding: utf-8 -*-

from flask_apispec import MethodResource
from flask_apispec import use_kwargs
from flask_apispec import marshal_with
from marshmallow import fields, validate
from restapi.rest.definition import EndpointResource
from restapi.models import Schema
from restapi import decorators
from restapi.services.detect import detector
from restapi.exceptions import RestApiException
from restapi.utilities.meta import Meta
from restapi.utilities.logs import log

auth = EndpointResource.load_authentication()


class NewPassword(Schema):
    password = fields.Str(
        required=True,
        password=True,
        validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH)
    )
    new_password = fields.Str(
        required=True,
        password=True,
        validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH)
    )
    password_confirm = fields.Str(
        required=True,
        password=True,
        validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH)
    )
    totp_code = fields.Str(required=False)


class UserProfile(Schema):
    name = fields.Str()
    surname = fields.Str()
    privacy_accepted = fields.Boolean()


class Group(Schema):
    uuid = fields.Str()
    shortname = fields.Str()
    fullname = fields.Str()


class ProfileData(Schema):
    uuid = fields.Str(required=True)
    email = fields.Email(required=True)
    name = fields.Str(required=True)
    surname = fields.Str(required=True)
    isAdmin = fields.Boolean(required=True)
    isLocalAdmin = fields.Boolean(required=True)
    privacy_accepted = fields.Boolean(required=True)
    roles = fields.Dict(required=True)

    group = fields.Nested(Group, required=False)

    SECOND_FACTOR = fields.Str(required=False)
    # Add custom fields from CustomProfile


class Profile(MethodResource, EndpointResource):
    """ Current user informations """

    baseuri = "/auth"
    depends_on = ["not PROFILE_DISABLED"]
    labels = ["profile"]

    auth_service = detector.authentication_service
    neo4j_enabled = auth_service == 'neo4j'
    sql_enabled = auth_service == 'sqlalchemy'
    mongo_enabled = auth_service == 'mongo'

    _GET = {
        "/profile": {
            "summary": "List profile attributes",
            "responses": {
                "200": {"description": "Dictionary with all profile attributes"}
            },
        }
    }
    _PUT = {
        "/profile": {
            "summary": "Update user password",
            "responses": {"204": {"description": "Password updated"}},
        }
    }
    _PATCH = {
        "/profile": {
            "summary": "Update profile information",
            "responses": {"204": {"description": "Profile updated"}},
        }
    }

    @decorators.catch_errors()
    @decorators.auth.required()
    @marshal_with(ProfileData, code=200)
    def get(self):

        current_user = self.auth.get_user()
        data = {
            'uuid': current_user.uuid,
            'email': current_user.email,
            'name': current_user.name,
            'surname': current_user.surname,
            'isAdmin': self.auth.verify_admin(),
            'isLocalAdmin': self.auth.verify_local_admin(),
            'privacy_accepted': current_user.privacy_accepted,
            # Convert list of Roles into a dict with name: description
            'roles': {
                role.name: role.description for role in current_user.roles
            }
        }
        if self.neo4j_enabled:
            data["group"] = current_user.belongs_to.single()

        if self.auth.SECOND_FACTOR_AUTHENTICATION:
            data['SECOND_FACTOR'] = self.auth.SECOND_FACTOR_AUTHENTICATION

        obj = Meta.get_customizer_class('apis.profile', 'CustomProfile')
        if obj is not None:
            try:
                data = obj.manipulate(ref=self, user=current_user, data=data)
            except BaseException as e:
                log.error("Could not custom manipulate profile:\n{}", e)

        return self.response(data)

    @decorators.catch_errors()
    @decorators.auth.required()
    @use_kwargs(NewPassword)
    def put(self, **kwargs):
        """ Update password for current user """

        user = self.auth.get_user()

        password = kwargs.get('password')
        new_password = kwargs.get('new_password')
        password_confirm = kwargs.get('password_confirm')

        totp_authentication = self.auth.SECOND_FACTOR_AUTHENTICATION == self.auth.TOTP

        if totp_authentication:
            totp_code = kwargs.get('totp_code')
            self.auth.verify_totp(user, totp_code)
        else:
            self.auth.make_login(user.email, password)

        self.auth.change_password(user, password, new_password, password_confirm)

        self.auth.save_user(user)

        return self.empty_response()

    @decorators.catch_errors()
    @decorators.auth.required()
    @use_kwargs(UserProfile)
    def patch(self, **kwargs):
        """ Update profile for current user """

        user = self.auth.get_user()

        if self.neo4j_enabled:
            self.update_properties(user, kwargs, kwargs)
        elif self.sql_enabled:
            self.update_sql_properties(user, kwargs, kwargs)
        elif self.mongo_enabled:
            self.update_mongo_properties(user, kwargs, kwargs)
        else:
            raise RestApiException(  # pragma: no cover
                "Invalid auth backend, all known db are disabled"
            )
        log.info("Profile updated")

        self.auth.save_user(user)

        return self.empty_response()
