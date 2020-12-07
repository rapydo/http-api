from restapi import decorators
from restapi.models import ISO8601UTC, Schema, fields, validate
from restapi.rest.definition import EndpointResource
from restapi.services.detect import detector
from restapi.utilities.globals import mem
from restapi.utilities.logs import log

auth = detector.get_authentication_instance()


class NewPassword(Schema):
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


def patchUserProfile():
    attributes = {}
    attributes["name"] = fields.Str()
    attributes["surname"] = fields.Str()
    attributes["privacy_accepted"] = fields.Boolean()

    if custom_fields := mem.customizer.get_custom_input_fields(
        request=None, scope=mem.customizer.PROFILE
    ):
        attributes.update(custom_fields)

    schema = Schema.from_dict(attributes)
    return schema()


# Duplicated in admin_users.py
class Group(Schema):
    uuid = fields.UUID()
    shortname = fields.Str()
    fullname = fields.Str()


def getProfileData():
    attributes = {}

    attributes["uuid"] = fields.UUID(required=True)
    attributes["email"] = fields.Email(required=True)
    attributes["name"] = fields.Str(required=True)
    attributes["surname"] = fields.Str(required=True)
    attributes["isAdmin"] = fields.Boolean(required=True)
    attributes["isStaff"] = fields.Boolean(required=True)
    attributes["isCoordinator"] = fields.Boolean(required=True)
    attributes["privacy_accepted"] = fields.Boolean(required=True)
    attributes["is_active"] = fields.Boolean(required=True)
    attributes["roles"] = fields.Dict(required=True)
    attributes["last_password_change"] = fields.DateTime(
        required=True, format=ISO8601UTC
    )
    attributes["first_login"] = fields.DateTime(required=True, format=ISO8601UTC)
    attributes["last_login"] = fields.DateTime(required=True, format=ISO8601UTC)

    attributes["group"] = fields.Nested(Group)

    attributes["SECOND_FACTOR"] = fields.Str(required=False)

    if custom_fields := mem.customizer.get_custom_output_fields(None):
        attributes.update(custom_fields)

    schema = Schema.from_dict(attributes)
    return schema()


class Profile(EndpointResource):

    baseuri = "/auth"
    depends_on = ["not PROFILE_DISABLED"]
    labels = ["profile"]

    @decorators.auth.require()
    @decorators.marshal_with(getProfileData(), code=200)
    @decorators.endpoint(
        path="/profile",
        summary="List profile attributes",
        responses={200: "User profile is returned"},
    )
    def get(self):

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
            # Convert list of Roles into a dict with name: description
            "roles": {role.name: role.description for role in current_user.roles},
        }

        if detector.authentication_service == "neo4j":
            data["group"] = current_user.belongs_to.single()
        else:
            data["group"] = current_user.belongs_to

        if self.auth.SECOND_FACTOR_AUTHENTICATION:
            data["SECOND_FACTOR"] = self.auth.SECOND_FACTOR_AUTHENTICATION

        data = mem.customizer.manipulate_profile(ref=self, user=current_user, data=data)

        return self.response(data)

    @decorators.auth.require()
    @decorators.use_kwargs(NewPassword)
    @decorators.endpoint(
        path="/profile",
        summary="Update user password",
        responses={204: "Password updated"},
    )
    def put(self, password, new_password, password_confirm, totp_code=None):
        """ Update password for current user """

        user = self.get_user()

        totp_authentication = self.auth.SECOND_FACTOR_AUTHENTICATION == self.auth.TOTP

        if totp_authentication:
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
    def patch(self, **kwargs):
        """ Update profile for current user """

        user = self.get_user()

        self.auth.db.update_properties(user, kwargs)

        log.info("Profile updated")

        self.auth.save_user(user)

        return self.empty_response()
