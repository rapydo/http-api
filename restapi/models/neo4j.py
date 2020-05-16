# -*- coding: utf-8 -*-

""" Models for graph database """

from neomodel import (
    StructuredNode,
    StringProperty,
    DateTimeProperty,
    EmailProperty,
    BooleanProperty,
    RelationshipTo,
    RelationshipFrom,

    OneOrMore,
    ZeroOrMore,
    ZeroOrOne
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
    tokens = RelationshipTo('Token', 'HAS_TOKEN', cardinality=ZeroOrMore)
    roles = RelationshipTo('Role', 'HAS_ROLE', cardinality=ZeroOrMore)


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
    emitted_for = RelationshipFrom('User', 'HAS_TOKEN', cardinality=ZeroOrOne)


class Role(StructuredNode):
    name = StringProperty(required=True, unique_index=True)
    description = StringProperty(default='No description')
    privileged = RelationshipFrom(User, 'HAS_ROLE', cardinality=OneOrMore)
