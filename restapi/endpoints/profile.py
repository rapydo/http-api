from typing import Any, Dict, Optional, Union

from restapi import decorators
from restapi.connectors import Connector
from restapi.models import ISO8601UTC, TOTP, Schema, fields, validate
from restapi.rest.definition import EndpointResource, Response
from restapi.utilities.globals import mem
from restapi.utilities.logs import log

auth = Connector.get_authentication_instance()


class NewPassword(Schema):
    password = fields.Str(
        required=True,
        password=True,
        # Not needed to check the length of the current password... if set...
        # validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
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
    totp_code = TOTP(required=False)


def patchUserProfile():
    # as defined in Marshmallow.schema.from_dict
    attributes: Dict[str, Union[fields.Field, type]] = {}

    attributes["name"] = fields.Str()
    attributes["surname"] = fields.Str()
    attributes["privacy_accepted"] = fields.Boolean()

    if custom_fields := mem.customizer.get_custom_input_fields(
        request=None, scope=mem.customizer.PROFILE
    ):
        attributes.update(custom_fields)

    schema = Schema.from_dict(attributes, name="UserProfileEdit")
    return schema()


# Duplicated in admin_users.py
class Group(Schema):
    uuid = fields.UUID()
    shortname = fields.Str()
    fullname = fields.Str()


def getProfileData():
    # as defined in Marshmallow.schema.from_dict
    attributes: Dict[str, Union[fields.Field, type]] = {}

    attributes["uuid"] = fields.UUID(required=True)
    attributes["email"] = fields.Email(required=True)
    attributes["name"] = fields.Str(required=True)
    attributes["surname"] = fields.Str(required=True)
    attributes["isAdmin"] = fields.Boolean(required=True)
    attributes["isStaff"] = fields.Boolean(required=True)
    attributes["isCoordinator"] = fields.Boolean(required=True)
    attributes["privacy_accepted"] = fields.Boolean(required=True)
    attributes["is_active"] = fields.Boolean(required=True)
    attributes["expiration"] = fields.DateTime(allow_none=True, format=ISO8601UTC)
    attributes["roles"] = fields.Dict(required=True)
    attributes["last_password_change"] = fields.DateTime(
        required=True, format=ISO8601UTC
    )
    attributes["first_login"] = fields.DateTime(required=True, format=ISO8601UTC)
    attributes["last_login"] = fields.DateTime(required=True, format=ISO8601UTC)

    attributes["group"] = fields.Nested(Group)

    attributes["two_factor_enabled"] = fields.Boolean(required=True)

    if custom_fields := mem.customizer.get_custom_output_fields(None):
        attributes.update(custom_fields)

    schema = Schema.from_dict(attributes, name="UserProfile")
    return schema()


class Profile(EndpointResource):

    baseuri = "/auth"
    depends_on = ["MAIN_LOGIN_ENABLE"]
    labels = ["profile"]

    @decorators.auth.require()
    @decorators.marshal_with(getProfileData(), code=200)
    @decorators.endpoint(
        path="/profile",
        summary="List profile attributes",
        responses={200: "User profile is returned"},
    )
    def get(self) -> Response:

        current_user = self.get_user()
        data = {
            "uuid": current_user.uuid,
            "email": current_user.email,
            "name": current_user.name,
            "surname": current_user.surname,
            "isAdmin": self.verify_admin(),
            "isStaff": self.verify_staff(),
            "isCoordinator": self.verify_coordinator(),
            "privacy_accepted": current_user.privacy_accepted,
            "last_password_change": current_user.last_password_change,
            "first_login": current_user.first_login,
            "last_login": current_user.last_login,
            "is_active": current_user.is_active,
            "expiration": current_user.expiration,
            # Convert list of Roles into a dict with name: description
            "roles": {role.name: role.description for role in current_user.roles},
        }

        if Connector.authentication_service == "neo4j":
            data["group"] = current_user.belongs_to.single()
        else:
            data["group"] = current_user.belongs_to

        data["two_factor_enabled"] = self.auth.SECOND_FACTOR_AUTHENTICATION

        data = mem.customizer.manipulate_profile(ref=self, user=current_user, data=data)

        return self.response(data)

    @decorators.auth.require()
    @decorators.use_kwargs(NewPassword)
    @decorators.endpoint(
        path="/profile",
        summary="Update user password",
        responses={204: "Password updated"},
    )
    def put(
        self,
        password: str,
        new_password: str,
        password_confirm: str,
        totp_code: Optional[str] = None,
    ) -> Response:
        """ Update password for current user """

        user = self.get_user()

        if self.auth.SECOND_FACTOR_AUTHENTICATION:
            self.auth.verify_totp(user, totp_code)

        self.auth.make_login(user.email, password)

        self.auth.change_password(user, password, new_password, password_confirm)

        self.auth.save_user(user)

        return self.empty_response()

    @decorators.auth.require()
    @decorators.use_kwargs(patchUserProfile())
    @decorators.endpoint(
        path="/profile",
        summary="Update profile information",
        responses={204: "Profile updated"},
    )
    def patch(self, **kwargs: Any) -> Response:
        """ Update profile for current user """

        user = self.get_user()

        self.auth.db.update_properties(user, kwargs)

        log.info("Profile updated")

        self.auth.save_user(user)

        self.log_event(self.events.modify, user, kwargs)
        return self.empty_response()
