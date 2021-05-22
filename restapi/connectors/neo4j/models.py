""" Models for graph database """
from typing import Type

from neomodel import (
    AliasProperty,
    ArrayProperty,
    BooleanProperty,
    DateProperty,
    DateTimeProperty,
    EmailProperty,
    FloatProperty,
    IntegerProperty,
    JSONProperty,
    OneOrMore,
    RelationshipFrom,
    RelationshipTo,
    StringProperty,
    StructuredNode,
    StructuredRel,
    ZeroOrMore,
    ZeroOrOne,
)

from restapi.config import TESTING
from restapi.connectors.neo4j.types import IdentifiedNode, TimestampedNode
from restapi.utilities.meta import Meta

# mypy: ignore-errors
UserCustomClass: Type[IdentifiedNode] = (
    Meta.get_class("models.neo4j", "UserCustom") or IdentifiedNode
)
# mypy: ignore-errors
GroupCustomClass: Type[IdentifiedNode] = (
    Meta.get_class("models.neo4j", "GroupCustom") or IdentifiedNode
)


class User(UserCustomClass):
    email = EmailProperty(required=True, unique_index=True)
    name = StringProperty(required=True)
    surname = StringProperty(required=True)
    authmethod = StringProperty(required=True)
    password = StringProperty(required=True)
    mfa_hash = StringProperty()
    first_login = DateTimeProperty()
    last_login = DateTimeProperty()
    last_password_change = DateTimeProperty()
    is_active = BooleanProperty(default=True)
    privacy_accepted = BooleanProperty(default=True)
    expiration = DateTimeProperty()

    tokens = RelationshipTo("Token", "HAS_TOKEN", cardinality=ZeroOrMore)
    roles = RelationshipTo("Role", "HAS_ROLE", cardinality=ZeroOrMore)
    belongs_to = RelationshipTo("Group", "BELONGS_TO")
    logins = RelationshipTo("Login", "HAS_LOGIN", cardinality=ZeroOrMore)


class Group(GroupCustomClass):
    shortname = StringProperty(required=True, unique_index=True)
    fullname = StringProperty(required=True, unique_index=False)

    members = RelationshipFrom("User", "BELONGS_TO", cardinality=ZeroOrMore)


class Token(StructuredNode):
    jti = StringProperty(required=True, unique_index=True)
    token = StringProperty(required=True, unique_index=True)
    token_type = StringProperty(required=True)
    creation = DateTimeProperty(required=True)
    expiration = DateTimeProperty()
    last_access = DateTimeProperty()
    IP = StringProperty()
    location = StringProperty()
    emitted_for = RelationshipFrom("User", "HAS_TOKEN", cardinality=ZeroOrOne)


class Role(StructuredNode):
    name = StringProperty(required=True, unique_index=True)
    description = StringProperty(default="No description")
    privileged = RelationshipFrom(User, "HAS_ROLE", cardinality=OneOrMore)


class Login(StructuredNode):
    date = DateTimeProperty(required=True)
    username = StringProperty()
    IP = StringProperty()
    location = StringProperty()
    user = RelationshipFrom("User", "HAS_LOGIN", cardinality=ZeroOrOne)
    failed = BooleanProperty(default=False)
    flushed = BooleanProperty(default=False)


if TESTING:

    class RelationTest(StructuredRel):
        pp = StringProperty()

    class NodeTest(TimestampedNode):
        p_str = StringProperty(required=True)
        p_int = IntegerProperty()
        p_arr = ArrayProperty()
        p_json = JSONProperty()
        p_float = FloatProperty()
        p_date = DateProperty()
        p_dt = DateTimeProperty()
        p_bool = BooleanProperty()
        p_alias = AliasProperty()

        test1 = RelationshipFrom(
            "restapi.connectors.neo4j.models.User",
            "TEST",
            cardinality=ZeroOrMore,
            model=RelationTest,
        )

        test2 = RelationshipFrom(
            "restapi.connectors.neo4j.models.User",
            "TEST2",
            cardinality=ZeroOrMore,
            model=RelationTest,
        )
