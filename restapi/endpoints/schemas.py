from datetime import datetime
from typing import Dict, Type, TypedDict, Union

from restapi.connectors import Connector
from restapi.customizer import FlaskRequest
from restapi.models import ISO8601UTC, Schema, fields, validate
from restapi.utilities.globals import mem

auth = Connector.get_authentication_instance()

# as defined in Marshmallow.schema.from_dict
MarshmallowSchema = Dict[str, Union[fields.Field, type]]

#########################################
# #############   Schemas   #############
#########################################


class User(Schema):
    email = fields.Email()
    name = fields.Str()
    surname = fields.Str()


class UserWithUUID(Schema):
    uuid = fields.UUID()
    email = fields.Email()
    name = fields.String()
    surname = fields.String()


class Role(Schema):
    name = fields.Str()
    description = fields.Str()


class Group(Schema):
    uuid = fields.UUID()
    fullname = fields.Str()
    shortname = fields.Str()


# Output Schema
class GroupWithMembers(Schema):
    uuid = fields.UUID()
    fullname = fields.Str()
    shortname = fields.Str()

    members = fields.Nested(UserWithUUID(many=True))
    coordinators = fields.Nested(UserWithUUID(many=True))


class TokenSchema(Schema):
    id = fields.Str()
    IP = fields.Str()
    location = fields.Str()
    token = fields.Str()
    emitted = fields.DateTime(format=ISO8601UTC)
    expiration = fields.DateTime(format=ISO8601UTC)
    last_access = fields.DateTime(format=ISO8601UTC)


class TokenAdminSchema(TokenSchema):
    # token_type = fields.Str()
    user = fields.Nested(User)


class TotalSchema(Schema):
    total = fields.Int()


class Credentials(Schema):
    username = fields.Email(required=True, validate=validate.Length(max=100))
    password = fields.Str(
        required=True,
        metadata={"password": True},
        # Otherwise default testing password, like test, will fail
        # validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH)
    )
    new_password = fields.Str(
        required=False,
        validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
        metadata={"password": True},
    )
    password_confirm = fields.Str(
        required=False,
        validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
        metadata={"password": True},
    )
    totp_code = fields.TOTP(required=False)


class NewPassword(Schema):
    password = fields.Str(
        required=True,
        metadata={"password": True},
        # Not needed to check the length of the current password... if set...
        # validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
    )
    new_password = fields.Str(
        required=True,
        validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
        metadata={"password": True},
    )
    password_confirm = fields.Str(
        required=True,
        validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
        metadata={"password": True},
    )
    totp_code = fields.TOTP(required=False)


class MailInput(Schema):
    subject = fields.Str(
        required=True, metadata={"description": "Subject of your email"}
    )
    body = fields.Str(
        required=True,
        validate=validate.Length(max=9999),
        metadata={"description": "Body of your email. You can use html code here."},
    )
    to = fields.Email(required=True, metadata={"label": "Destination email address"})
    cc = fields.DelimitedList(
        fields.Email(),
        metadata={
            "label": "CC - Carbon Copy",
            "description": "CC email addresses (comma-delimited list)",
        },
    )
    bcc = fields.DelimitedList(
        fields.Email(),
        metadata={
            "label": "BCC - Blind Carbon Copy",
            "description": "BCC email addresses (comma-delimited list)",
        },
    )
    dry_run = fields.Boolean(
        required=True,
        metadata={
            "label": "Dry run execution",
            "description": "Only simulate the email, do not send it",
        },
    )


class MailOutput(Schema):
    html_body = fields.Str()
    plain_body = fields.Str()
    subject = fields.Str()
    to = fields.Email()
    cc = fields.List(fields.Email())
    bcc = fields.List(fields.Email())


class LoginsSchema(Schema):
    username = fields.Email()
    date = fields.DateTime(format=ISO8601UTC)
    IP = fields.Str()
    location = fields.Str()
    failed = fields.Boolean()
    flushed = fields.Boolean()


#########################################
# ############   Callbacks   ############
#########################################

# Note that these are callables returning a model, not models!
# They will be executed a runtime


def admin_user_output(many: bool = True) -> Schema:
    attributes: MarshmallowSchema = {}

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
    attributes["roles"] = fields.List(fields.Nested(Role))
    attributes["expiration"] = fields.DateTime(allow_none=True, format=ISO8601UTC)

    if Connector.authentication_service == "neo4j":
        attributes["belongs_to"] = fields.Neo4jRelationshipToSingle(
            Group, data_key="group"
        )
    else:
        attributes["belongs_to"] = fields.Nested(Group, data_key="group")

    if custom_fields := mem.customizer.get_custom_output_fields(None):
        attributes.update(custom_fields)

    schema = Schema.from_dict(attributes, name="UserData")
    return schema(many=many)  # type: ignore


def group_users_output() -> Schema:
    attributes: MarshmallowSchema = {}

    attributes["email"] = fields.Email()
    attributes["name"] = fields.Str()
    attributes["surname"] = fields.Str()
    attributes["roles"] = fields.List(fields.Nested(Role))

    if custom_fields := mem.customizer.get_custom_output_fields(None):
        attributes.update(custom_fields)

    schema = Schema.from_dict(attributes, name="UserData")
    return schema(many=True)  # type: ignore


# Can't use request.method because it is not passed at loading time, i.e. the Specs will
# be created with empty request
def admin_user_input(request: FlaskRequest, is_post: bool) -> Type[Schema]:

    attributes: MarshmallowSchema = {}
    if is_post:
        attributes["email"] = fields.Email(
            required=is_post, validate=validate.Length(max=100)
        )

    attributes["name"] = fields.Str(
        required=is_post,
        validate=validate.Length(min=1),
        metadata={"label": "First Name"},
    )
    attributes["surname"] = fields.Str(
        required=is_post,
        validate=validate.Length(min=1),
        metadata={"label": "Last Name"},
    )

    attributes["password"] = fields.Str(
        required=is_post,
        validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
        metadata={"password": True},
    )

    if Connector.check_availability("smtp"):
        attributes["email_notification"] = fields.Bool(
            metadata={"label": "Notify password by email"}
        )

    attributes["is_active"] = fields.Bool(
        dump_default=True,
        required=False,
        metadata={"label": "Activate user"},
    )

    roles = {r.name: r.description for r in auth.get_roles()}

    attributes["roles"] = fields.List(
        fields.Str(
            validate=validate.OneOf(
                choices=[r for r in roles.keys()],
                labels=[r for r in roles.values()],
            )
        ),
        dump_default=[auth.default_role],
        required=False,
        unique=True,
        metadata={
            "label": "Roles",
            "description": "",
        },
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
        required=is_post,
        dump_default=default_group,
        validate=validate.OneOf(choices=group_keys, labels=group_labels),
        metadata={
            "label": "Group",
            "description": "The group to which the user belongs",
        },
    )

    attributes["expiration"] = fields.DateTime(
        required=False,
        allow_none=True,
        metadata={
            "label": "Account expiration",
            "description": "This user will be blocked after this date",
        },
    )

    if custom_fields := mem.customizer.get_custom_input_fields(
        request=request, scope=mem.customizer.ADMIN
    ):
        attributes.update(custom_fields)

    return Schema.from_dict(attributes, name="UserDefinition")


def admin_user_post_input(request: FlaskRequest) -> Type[Schema]:
    return admin_user_input(request, True)


def admin_user_put_input(request: FlaskRequest) -> Type[Schema]:
    return admin_user_input(request, False)


# Should to transformed again in a Schema
def admin_group_input(request: FlaskRequest) -> Type[Schema]:

    attributes: MarshmallowSchema = {}

    attributes["shortname"] = fields.Str(
        required=True, metadata={"description": "Short name"}
    )
    attributes["fullname"] = fields.Str(
        required=True, metadata={"description": "Full name"}
    )

    return Schema.from_dict(attributes, name="GroupDefinition")


def profile_patch_input() -> Schema:
    attributes: MarshmallowSchema = {}

    attributes["name"] = fields.Str(metadata={"label": "First Name"})
    attributes["surname"] = fields.Str(metadata={"label": "Last Name"})
    attributes["privacy_accepted"] = fields.Boolean()

    if custom_fields := mem.customizer.get_custom_input_fields(
        request=None, scope=mem.customizer.PROFILE
    ):
        attributes.update(custom_fields)

    schema = Schema.from_dict(attributes, name="UserProfileEdit")
    return schema()  # type: ignore


def profile_output() -> Schema:
    attributes: MarshmallowSchema = {}

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

    if Connector.authentication_service == "neo4j":
        attributes["belongs_to"] = fields.Neo4jRelationshipToSingle(
            Group, data_key="group"
        )
    else:
        attributes["belongs_to"] = fields.Nested(Group, data_key="group")

    attributes["two_factor_enabled"] = fields.Boolean(required=True)

    if custom_fields := mem.customizer.get_custom_output_fields(None):
        attributes.update(custom_fields)

    schema = Schema.from_dict(attributes, name="UserProfile")
    return schema()  # type: ignore


def user_registration_input(request: FlaskRequest) -> Type[Schema]:

    attributes: MarshmallowSchema = {}

    attributes["name"] = fields.Str(required=True)
    attributes["surname"] = fields.Str(required=True)
    attributes["email"] = fields.Email(
        required=True,
        metadata={"label": "Username (email address)"},
        validate=validate.Length(max=100),
    )
    attributes["password"] = fields.Str(
        required=True,
        validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
        metadata={"password": True},
    )
    attributes["password_confirm"] = fields.Str(
        required=True,
        validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH),
        metadata={"label": "Password confirmation", "password": True},
    )

    if custom_fields := mem.customizer.get_custom_input_fields(
        request=None, scope=mem.customizer.REGISTRATION
    ):
        attributes.update(custom_fields)

    return Schema.from_dict(attributes, name="UserRegistration")


#########################################
# ##########   Stats Schemas   ##########
#########################################


class SystemSchema(Schema):
    boot_time = fields.DateTime(format=ISO8601UTC)


class CPUSchema(Schema):
    count = fields.Int()
    load_percentage = fields.Decimal(places=2)
    user = fields.Int()
    system = fields.Int()
    idle = fields.Int()
    wait = fields.Int()
    stolen = fields.Int()


class RAMSchema(Schema):
    total = fields.Int()
    used = fields.Int()
    active = fields.Int()
    inactive = fields.Int()
    buffer = fields.Int()
    free = fields.Int()
    cache = fields.Int()


class SwapSchema(Schema):
    from_disk = fields.Int()
    to_disk = fields.Int()
    total = fields.Int()
    used = fields.Int()
    free = fields.Int()


class DiskSchema(Schema):
    total_disk_space = fields.Decimal(places=2)
    used_disk_space = fields.Decimal(places=2)
    free_disk_space = fields.Decimal(places=2)
    occupacy = fields.Decimal(places=2)


class ProcSchema(Schema):
    waiting_for_run = fields.Int()
    uninterruptible_sleep = fields.Int()


class IOSchema(Schema):
    blocks_received = fields.Int()
    blocks_sent = fields.Int()


class NetworkSchema(Schema):
    min = fields.Decimal(places=2)
    max = fields.Decimal(places=2)
    avg = fields.Decimal(places=2)


class StatsSchema(Schema):
    system = fields.Nested(SystemSchema)
    cpu = fields.Nested(CPUSchema)
    ram = fields.Nested(RAMSchema)
    swap = fields.Nested(SwapSchema)
    disk = fields.Nested(DiskSchema)
    procs = fields.Nested(ProcSchema)
    io = fields.Nested(IOSchema)
    network_latency = fields.Nested(NetworkSchema)


class SystemType(TypedDict):
    boot_time: datetime


class CPUType(TypedDict):
    count: int
    load_percentage: float
    user: int
    system: int
    idle: int
    wait: int
    stolen: int


class RAMType(TypedDict):
    total: int
    used: int
    active: int
    inactive: int
    buffer: int
    free: int
    cache: int


class SwapType(TypedDict):
    from_disk: int
    to_disk: int
    total: int
    used: int
    free: int


class DiskType(TypedDict):
    total_disk_space: float
    used_disk_space: float
    free_disk_space: float
    occupacy: float


class ProcType(TypedDict):
    waiting_for_run: int
    uninterruptible_sleep: int


class IOType(TypedDict):
    blocks_received: int
    blocks_sent: int


class NetworkType(TypedDict):
    min: float
    max: float
    avg: float


class StatsType(TypedDict):
    system: SystemType
    cpu: CPUType
    ram: RAMType
    swap: SwapType
    disk: DiskType
    procs: ProcType
    io: IOType
    network_latency: NetworkType
