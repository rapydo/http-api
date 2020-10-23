from restapi import decorators
from restapi.confs import get_project_configuration
from restapi.exceptions import DatabaseDuplicatedEntry, RestApiException
from restapi.models import Schema, fields, validate
from restapi.rest.definition import EndpointResource
from restapi.services.authentication import ROLE_DISABLED, BaseAuthentication, Role
from restapi.services.detect import detector
from restapi.utilities.globals import mem
from restapi.utilities.logs import log
from restapi.utilities.templates import get_html_template


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


def get_roles(auth):

    roles = {}
    for r in auth.get_roles():

        if r.description == ROLE_DISABLED:
            continue

        roles[f"roles_{r.name}"] = r.description

    return roles


def parse_roles(properties):

    roles = []
    for p in properties.copy():
        if not p.startswith("roles_"):
            continue
        if properties.get(p):
            roles.append(p[6:])
        properties.pop(p)

    return roles


def parse_group(v, neo4j):
    group_id = v.pop("group", None)
    if group_id is None:
        raise RestApiException("Group not found", status_code=400)
    group = neo4j.Group.nodes.get_or_none(uuid=group_id)

    if group is None:
        raise RestApiException("Group not found", status_code=400)

    return group


def get_groups():
    auth_service = detector.authentication_service

    if auth_service == "neo4j":

        neo4j = detector.get_service_instance("neo4j")

        groups = {}
        for g in neo4j.Group.nodes.all():
            group_name = f"{g.shortname} - {g.fullname}"
            groups[g.uuid] = group_name

        return groups

    if auth_service == "sqlalchemy":
        return None

    if auth_service == "mongo":
        return None

    log.error("Unknown auth service: {}", auth_service)  # pragma: no cover


class Roles(Schema):

    name = fields.Str()
    description = fields.Str()


# Duplicated in profile.py
class Group(Schema):
    uuid = fields.UUID()
    fullname = fields.Str()
    shortname = fields.Str()


def get_output_schema():
    attributes = {}

    attributes["uuid"] = fields.UUID()
    attributes["email"] = fields.Email()
    attributes["name"] = fields.Str()
    attributes["surname"] = fields.Str()
    attributes["first_login"] = fields.DateTime(allow_none=True)
    attributes["last_login"] = fields.DateTime(allow_none=True)
    attributes["last_password_change"] = fields.DateTime(allow_none=True)
    attributes["is_active"] = fields.Boolean()
    attributes["privacy_accepted"] = fields.Boolean()
    attributes["roles"] = fields.List(fields.Nested(Roles))

    attributes["belongs_to"] = fields.List(fields.Nested(Group), data_key="group")
    attributes["coordinator"] = fields.List(fields.Nested(Group))

    if custom_fields := mem.customizer.get_custom_output_fields(None):
        attributes.update(custom_fields)

    schema = Schema.from_dict(attributes)
    return schema(many=True)


# Note that these are callables returning a model, not models!
# They will be executed a runtime
def getInputSchema(request):

    if not request:
        return {}

    auth = EndpointResource.load_authentication()

    set_required = request.method == "POST"

    attributes = {}
    if request.method != "PUT":
        attributes["email"] = fields.Email(required=set_required)

    attributes["name"] = fields.Str(
        required=set_required, validate=validate.Length(min=1)
    )
    attributes["surname"] = fields.Str(
        required=set_required, validate=validate.Length(min=1)
    )

    attributes["password"] = fields.Str(
        required=set_required,
        password=True,
        validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
    )

    if detector.check_availability("smtp"):
        attributes["email_notification"] = fields.Bool(label="Notify password by email")

    attributes["is_active"] = fields.Bool(
        label="Activate user", default=True, required=False
    )

    for key, label in get_roles(auth).items():
        attributes[key] = fields.Bool(label=label)

    groups = get_groups()
    if groups:
        attributes["group"] = fields.Str(
            required=set_required,
            validate=validate.OneOf(choices=groups.keys(), labels=groups.values()),
        )

    if custom_fields := mem.customizer.get_custom_input_fields(request):
        attributes.update(custom_fields)

    return Schema.from_dict(attributes)


class AdminUsers(EndpointResource):

    auth_service = detector.authentication_service
    neo4j_enabled = auth_service == "neo4j"
    sql_enabled = auth_service == "sqlalchemy"
    mongo_enabled = auth_service == "mongo"

    depends_on = ["not ADMINER_DISABLED"]
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
    def get(self, user_id=None):

        users = self.auth.get_users(user_id)
        if users is None:
            raise RestApiException(
                "This user cannot be found or you are not authorized"
            )

        return self.response(users)

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.use_kwargs(getInputSchema)
    @decorators.endpoint(
        path="/admin/users",
        summary="Create a new user",
        responses={
            200: "The uuid of the new user is returned",
            409: "This user already exists",
        },
    )
    def post(self, **kwargs):

        roles = parse_roles(kwargs)

        email_notification = kwargs.pop("email_notification", False)

        unhashed_password = kwargs["password"]

        # If created by admins users must accept privacy at first login
        kwargs["privacy_accepted"] = False

        try:
            user = self.auth.create_user(kwargs, roles)
            if self.sql_enabled:
                self.auth.db.session.commit()
        except DatabaseDuplicatedEntry as e:
            if self.sql_enabled:
                self.auth.db.session.rollback()
            raise RestApiException(str(e), status_code=409)

        # FIXME: groups management is only implemented for neo4j
        if "group" in kwargs and self.neo4j_enabled:
            self.graph = self.get_service_instance("neo4j")
            group = parse_group(kwargs, self.graph)

            if group is not None:
                user.belongs_to.connect(group)

        if email_notification and unhashed_password is not None:
            smtp = self.get_service_instance("smtp")
            send_notification(smtp, user, unhashed_password, is_update=False)

        return self.response(user.uuid)

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.use_kwargs(getInputSchema)
    @decorators.endpoint(
        path="/admin/users/<user_id>",
        summary="Modify a user",
        responses={200: "User successfully modified"},
    )
    def put(self, user_id, **kwargs):

        user = self.auth.get_users(user_id)

        if user is None:
            raise RestApiException(
                "This user cannot be found or you are not authorized"
            )

        user = user[0]

        if "password" in kwargs:
            unhashed_password = kwargs["password"]
            kwargs["password"] = BaseAuthentication.get_password_hash(
                kwargs["password"]
            )
        else:
            unhashed_password = None

        roles = parse_roles(kwargs)

        email_notification = kwargs.pop("email_notification", False)

        self.auth.link_roles(user, roles)
        db = self.get_service_instance(detector.authentication_service)
        if self.neo4j_enabled:
            self.graph = db

        userdata, extra_userdata = self.auth.custom_user_properties_pre(kwargs)

        db.update_properties(user, userdata)

        self.auth.custom_user_properties_post(user, userdata, extra_userdata, db)

        self.auth.save_user(user)

        # FIXME: groups management is only implemented for neo4j
        if "group" in kwargs and self.neo4j_enabled:

            group = parse_group(kwargs, self.graph)

            p = None
            for p in user.belongs_to.all():
                if p == group:
                    continue

            if p is not None:
                user.belongs_to.reconnect(p, group)
            else:
                user.belongs_to.connect(group)

        if email_notification and unhashed_password is not None:
            smtp = self.get_service_instance("smtp")
            send_notification(smtp, user, unhashed_password, is_update=True)

        return self.empty_response()

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.endpoint(
        path="/admin/users/<user_id>",
        summary="Delete a user",
        responses={200: "User successfully deleted"},
    )
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
            raise RestApiException(  # pragma: no cover
                "Invalid auth backend, all known db are disabled"
            )

        return self.empty_response()
