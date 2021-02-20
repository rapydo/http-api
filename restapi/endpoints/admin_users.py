from typing import Any, Dict, List, Optional, Union

from restapi import decorators
from restapi.config import get_project_configuration
from restapi.connectors import Connector, smtp
from restapi.exceptions import Conflict, DatabaseDuplicatedEntry, NotFound
from restapi.models import ISO8601UTC, AdvancedList, Schema, fields, validate
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import BaseAuthentication, Role
from restapi.utilities.globals import mem
from restapi.utilities.templates import get_html_template
from restapi.utilities.time import date_lower_than as dt_lower

# from restapi.utilities.logs import log


def send_notification(smtp, user, unhashed_password, is_update=False):

    title = get_project_configuration("project.title", default="Unkown title")

    if is_update:
        subject = f"{title}: password changed"
        template = "update_credentials.html"
    else:
        subject = f"{title}: new credentials"
        template = "new_credentials.html"

    replaces = {"username": user.email, "password": unhashed_password}

    html = get_html_template(template, replaces)

    body = f"""
Username: {user.email}
Password: {unhashed_password}
    """

    if html is None:
        smtp.send(body, subject, user.email)
    else:
        smtp.send(html, subject, user.email, plain_body=body)


class Roles(Schema):

    name = fields.Str()
    description = fields.Str()


# Duplicated in profile.py
class Group(Schema):
    uuid = fields.UUID()
    fullname = fields.Str()
    shortname = fields.Str()


def get_output_schema():
    # as defined in Marshmallow.schema.from_dict
    attributes: Dict[str, Union[fields.Field, type]] = {}

    attributes["uuid"] = fields.UUID()
    attributes["email"] = fields.Email()
    attributes["name"] = fields.Str()
    attributes["surname"] = fields.Str()
    attributes["first_login"] = fields.DateTime(allow_none=True, format=ISO8601UTC)
    attributes["last_login"] = fields.DateTime(allow_none=True, format=ISO8601UTC)
    attributes["last_password_change"] = fields.DateTime(
        allow_none=True, format=ISO8601UTC
    )
    attributes["is_active"] = fields.Boolean()
    attributes["privacy_accepted"] = fields.Boolean()
    attributes["roles"] = fields.List(fields.Nested(Roles))
    attributes["expiration"] = fields.DateTime(allow_none=True, format=ISO8601UTC)

    attributes["belongs_to"] = fields.Nested(Group, data_key="group")

    if custom_fields := mem.customizer.get_custom_output_fields(None):
        attributes.update(custom_fields)

    schema = Schema.from_dict(attributes, name="UserData")
    return schema(many=True)


auth = Connector.get_authentication_instance()


# Note that these are callables returning a model, not models!
# They will be executed a runtime
# Can't use request.method because it is not passed at loading time, i.e. the Specs will
# be created with empty request
def getInputSchema(request, is_post):

    # as defined in Marshmallow.schema.from_dict
    attributes: Dict[str, Union[fields.Field, type]] = {}
    if is_post:
        attributes["email"] = fields.Email(required=is_post)

    attributes["name"] = fields.Str(required=is_post, validate=validate.Length(min=1))
    attributes["surname"] = fields.Str(
        required=is_post, validate=validate.Length(min=1)
    )

    attributes["password"] = fields.Str(
        required=is_post,
        password=True,
        validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
    )

    if Connector.check_availability("smtp"):
        attributes["email_notification"] = fields.Bool(label="Notify password by email")

    attributes["is_active"] = fields.Bool(
        label="Activate user", default=True, required=False
    )

    roles = {r.name: r.description for r in auth.get_roles()}

    attributes["roles"] = AdvancedList(
        fields.Str(
            validate=validate.OneOf(
                choices=[r for r in roles.keys()],
                labels=[r for r in roles.values()],
            )
        ),
        required=False,
        label="Roles",
        description="",
        unique=True,
        multiple=True,
    )

    group_keys = []
    group_labels = []

    for g in auth.get_groups():
        group_keys.append(g.uuid)
        group_labels.append(f"{g.shortname} - {g.fullname}")

    if len(group_keys) == 1:
        default_group = group_keys[0]
    else:
        default_group = None

    attributes["group"] = fields.Str(
        label="Group",
        description="The group to which the user belongs",
        required=is_post,
        default=default_group,
        validate=validate.OneOf(choices=group_keys, labels=group_labels),
    )

    attributes["expiration"] = fields.DateTime(
        required=False,
        allow_none=True,
        label="Account expiration",
        description="This user will be blocked after this date",
    )

    if custom_fields := mem.customizer.get_custom_input_fields(
        request=request, scope=mem.customizer.ADMIN
    ):
        attributes.update(custom_fields)

    return Schema.from_dict(attributes, name="UserDefinition")


def getPOSTInputSchema(request):
    return getInputSchema(request, True)


def getPUTInputSchema(request):
    return getInputSchema(request, False)


class AdminUsers(EndpointResource):

    depends_on = ["MAIN_LOGIN_ENABLE"]
    labels = ["admin"]
    private = True

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.marshal_with(get_output_schema(), code=200)
    @decorators.endpoint(
        path="/admin/users",
        summary="List of users",
        responses={200: "List of users successfully retrieved"},
    )
    @decorators.endpoint(
        path="/admin/users/<user_id>",
        summary="Obtain information on a single user",
        responses={200: "User information successfully retrieved"},
    )
    def get(self, user_id: Optional[str] = None) -> Response:

        user = None
        users = None

        if not user_id:
            users = self.auth.get_users()
        elif user := self.auth.get_user(user_id=user_id):
            users = [user]

        if users is None:
            raise NotFound("This user cannot be found or you are not authorized")

        if Connector.authentication_service == "neo4j":
            for u in users:
                u.belongs_to = u.belongs_to.single()

        if user:
            self.log_event(self.events.access, user)

        return self.response(users)

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.use_kwargs(getPOSTInputSchema)
    @decorators.endpoint(
        path="/admin/users",
        summary="Create a new user",
        responses={
            200: "The uuid of the new user is returned",
            409: "This user already exists",
        },
    )
    def post(self, **kwargs: Any) -> Response:

        roles: List[str] = kwargs.pop("roles", [])
        payload = kwargs.copy()
        group_id = kwargs.pop("group")

        email_notification = kwargs.pop("email_notification", False)

        unhashed_password = kwargs["password"]

        # If created by admins users must accept privacy at first login
        kwargs["privacy_accepted"] = False

        try:
            user = self.auth.create_user(kwargs, roles)
            self.auth.save_user(user)
        except DatabaseDuplicatedEntry as e:
            if Connector.authentication_service == "sqlalchemy":
                self.auth.db.session.rollback()
            raise Conflict(str(e))

        group = self.auth.get_group(group_id=group_id)
        if not group:
            # Can't be reached because grup_id is prefiltered by marshmallow
            raise NotFound("This group cannot be found")  # pragma: no cover

        self.auth.add_user_to_group(user, group)

        if email_notification and unhashed_password is not None:
            smtp_client = smtp.get_instance()
            send_notification(smtp_client, user, unhashed_password, is_update=False)

        self.log_event(self.events.create, user, payload)

        return self.response(user.uuid)

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.use_kwargs(getPUTInputSchema)
    @decorators.endpoint(
        path="/admin/users/<user_id>",
        summary="Modify a user",
        responses={200: "User successfully modified"},
    )
    def put(self, user_id: str, **kwargs: Any) -> Response:

        user = self.auth.get_user(user_id=user_id)

        if user is None:
            raise NotFound("This user cannot be found or you are not authorized")

        if "password" in kwargs:
            unhashed_password = kwargs["password"]
            kwargs["password"] = BaseAuthentication.get_password_hash(
                kwargs["password"]
            )
        else:
            unhashed_password = None

        payload = kwargs.copy()
        roles: List[str] = kwargs.pop("roles", [])

        group_id = kwargs.pop("group", None)

        email_notification = kwargs.pop("email_notification", False)

        self.auth.link_roles(user, roles)

        userdata, extra_userdata = self.auth.custom_user_properties_pre(kwargs)

        prev_expiration = user.expiration

        self.auth.db.update_properties(user, userdata)

        self.auth.custom_user_properties_post(
            user, userdata, extra_userdata, self.auth.db
        )

        self.auth.save_user(user)

        if group_id is not None:
            group = self.auth.get_group(group_id=group_id)
            if not group:
                # Can't be reached because grup_id is prefiltered by marshmallow
                raise NotFound("This group cannot be found")  # pragma: no cover

            self.auth.add_user_to_group(user, group)

        if email_notification and unhashed_password is not None:
            smtp_client = smtp.get_instance()
            send_notification(smtp_client, user, unhashed_password, is_update=True)

        if user.expiration:
            # Set expiration on a previously non-expiring account
            # or update the expiration by reducing the validity period
            # In both cases tokens should be invalited to prevent to have tokens
            # with TTL > account validity

            # dt_lower (alias for date_lower_than) is a comparison fn that ignores tz
            if prev_expiration is None or dt_lower(user.expiration, prev_expiration):
                for token in self.auth.get_tokens(user=user):
                    # Invalidate all tokens with expiration after the account expiration
                    if dt_lower(user.expiration, token["expiration"]):
                        self.auth.invalidate_token(token=token["token"])

        self.log_event(self.events.modify, user, payload)

        return self.empty_response()

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.endpoint(
        path="/admin/users/<user_id>",
        summary="Delete a user",
        responses={200: "User successfully deleted"},
    )
    def delete(self, user_id: str) -> Response:

        user = self.auth.get_user(user_id=user_id)

        if user is None:
            raise NotFound("This user cannot be found or you are not authorized")

        self.auth.delete_user(user)

        self.log_event(self.events.delete, user)

        return self.empty_response()
