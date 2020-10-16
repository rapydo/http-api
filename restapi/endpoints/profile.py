from restapi import decorators
from restapi.models import Schema, fields, validate
from restapi.rest.definition import EndpointResource
from restapi.services.detect import detector
from restapi.utilities.globals import mem
from restapi.utilities.logs import log

auth = EndpointResource.load_authentication()


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

    if custom_fields := mem.customizer.get_user_editable_fields(None):
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
    attributes["isLocalAdmin"] = fields.Boolean(required=True)
    attributes["privacy_accepted"] = fields.Boolean(required=True)
    attributes["roles"] = fields.Dict(required=True)

    attributes["group"] = fields.Nested(Group, required=False)

    attributes["SECOND_FACTOR"] = fields.Str(required=False)

    if custom_fields := mem.customizer.get_custom_output_fields(None):
        attributes.update(custom_fields)

    schema = Schema.from_dict(attributes)
    return schema()


class Profile(EndpointResource):
    """ Current user informations """

    baseuri = "/auth"
    depends_on = ["not PROFILE_DISABLED"]
    labels = ["profile"]

    auth_service = detector.authentication_service
    neo4j_enabled = auth_service == "neo4j"

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
            "isLocalAdmin": self.verify_local_admin(),
            "privacy_accepted": current_user.privacy_accepted,
            # Convert list of Roles into a dict with name: description
            "roles": {role.name: role.description for role in current_user.roles},
        }
        if self.neo4j_enabled:
            data["group"] = current_user.belongs_to.single()

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

        db = self.get_service_instance(detector.authentication_service)
        db.update_properties(user, kwargs)

        log.info("Profile updated")

        self.auth.save_user(user)

        return self.empty_response()
