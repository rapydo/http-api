from flask_apispec import MethodResource, marshal_with, use_kwargs
from marshmallow import fields, validate

from restapi import decorators
from restapi.models import InputSchema, OutputSchema
from restapi.rest.definition import EndpointResource
from restapi.services.detect import detector
from restapi.utilities.logs import log
from restapi.utilities.meta import Meta

auth = EndpointResource.load_authentication()


class NewPassword(InputSchema):
    password = fields.Str(
        required=True,
        password=True,
        validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
    )
    new_password = fields.Str(
        required=True,
        password=True,
        validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
    )
    password_confirm = fields.Str(
        required=True,
        password=True,
        validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
    )
    totp_code = fields.Str(required=False)


class UserProfile(InputSchema):
    name = fields.Str()
    surname = fields.Str()
    privacy_accepted = fields.Boolean()


class Group(OutputSchema):
    uuid = fields.Str()
    shortname = fields.Str()
    fullname = fields.Str()


class ProfileData(OutputSchema):
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
    neo4j_enabled = auth_service == "neo4j"

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
            "uuid": current_user.uuid,
            "email": current_user.email,
            "name": current_user.name,
            "surname": current_user.surname,
            "isAdmin": self.auth.verify_admin(),
            "isLocalAdmin": self.auth.verify_local_admin(),
            "privacy_accepted": current_user.privacy_accepted,
            # Convert list of Roles into a dict with name: description
            "roles": {role.name: role.description for role in current_user.roles},
        }
        if self.neo4j_enabled:
            data["group"] = current_user.belongs_to.single()

        if self.auth.SECOND_FACTOR_AUTHENTICATION:
            data["SECOND_FACTOR"] = self.auth.SECOND_FACTOR_AUTHENTICATION

        CustomProfile = Meta.get_customizer_class("apis.profile", "CustomProfile")
        if CustomProfile is not None:
            data = CustomProfile.manipulate(ref=self, user=current_user, data=data)

        return self.response(data)

    @decorators.catch_errors()
    @decorators.auth.required()
    @use_kwargs(NewPassword)
    def put(self, password, new_password, password_confirm, totp_code=None):
        """ Update password for current user """

        user = self.auth.get_user()

        totp_authentication = self.auth.SECOND_FACTOR_AUTHENTICATION == self.auth.TOTP

        if totp_authentication:
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

        db = self.get_service_instance(detector.authentication_service)
        db.update_properties(user, kwargs, kwargs)

        log.info("Profile updated")

        self.auth.save_user(user)

        return self.empty_response()
