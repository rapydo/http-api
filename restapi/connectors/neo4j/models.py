""" Models for graph database """
from typing import Type

from neomodel import (
    BooleanProperty,
    DateTimeProperty,
    EmailProperty,
    OneOrMore,
    RelationshipFrom,
    RelationshipTo,
    StringProperty,
    StructuredNode,
    ZeroOrMore,
    ZeroOrOne,
)

from restapi.connectors.neo4j.types import IdentifiedNode
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
    password = StringProperty()
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


class Group(GroupCustomClass):
    shortname = StringProperty(required=True, unique_index=True)
    fullname = StringProperty(required=True, unique_index=False)

    members = RelationshipFrom("User", "BELONGS_TO", cardinality=ZeroOrMore)


class Token(StructuredNode):
    jti = StringProperty(required=True, unique_index=True)
    token = StringProperty(required=True, unique_index=True)
    token_type = StringProperty()
    creation = DateTimeProperty(required=True)
    expiration = DateTimeProperty()
    last_access = DateTimeProperty()
    IP = StringProperty()
    # no longer used
    hostname = StringProperty()
    location = StringProperty()
    emitted_for = RelationshipFrom("User", "HAS_TOKEN", cardinality=ZeroOrOne)


class Role(StructuredNode):
    name = StringProperty(required=True, unique_index=True)
    description = StringProperty(default="No description")
    privileged = RelationshipFrom(User, "HAS_ROLE", cardinality=OneOrMore)
