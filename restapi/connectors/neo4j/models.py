""" Models for graph database """

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


class User(IdentifiedNode):
    email = EmailProperty(required=True, unique_index=True)
    name = StringProperty(required=True)
    surname = StringProperty(required=True)
    authmethod = StringProperty(required=True)
    password = StringProperty()  # Hashed by a custom function
    first_login = DateTimeProperty()
    last_login = DateTimeProperty()
    last_password_change = DateTimeProperty()
    is_active = BooleanProperty(default=True)
    privacy_accepted = BooleanProperty(default=True)
    tokens = RelationshipTo("Token", "HAS_TOKEN", cardinality=ZeroOrMore)
    roles = RelationshipTo("Role", "HAS_ROLE", cardinality=ZeroOrMore)
    belongs_to = RelationshipTo("Group", "BELONGS_TO")
    coordinator = RelationshipTo("Group", "PI_FOR", cardinality=ZeroOrMore)


class Group(IdentifiedNode):
    fullname = StringProperty(required=True, unique_index=False)
    shortname = StringProperty(required=True, unique_index=True)

    members = RelationshipFrom("User", "BELONGS_TO", cardinality=ZeroOrMore)
    coordinator = RelationshipFrom("User", "PI_FOR", cardinality=ZeroOrOne)


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
