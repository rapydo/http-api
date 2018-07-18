# -*- coding: utf-8 -*-

""" Models for graph database """

from restapi.services.neo4j.models import \
    StructuredNode, IdentifiedNode, \
    StringProperty, DateTimeProperty, EmailProperty, BooleanProperty, \
    RelationshipTo, RelationshipFrom
from neomodel import OneOrMore, ZeroOrMore, ZeroOrOne


class User(IdentifiedNode):
    # uuid = StringProperty(required=True, unique_index=True)
    email = EmailProperty(required=True, unique_index=True, show=True)
    name = StringProperty(required=True, show=True)
    surname = StringProperty(required=True, show=True)
    authmethod = StringProperty(required=True)
    password = StringProperty()  # Hashed from a custom function
    first_login = DateTimeProperty(show=True)
    last_login = DateTimeProperty(show=True)
    last_password_change = DateTimeProperty(show=True)
    is_active = BooleanProperty(default=True, show=True)
    tokens = RelationshipTo('Token', 'HAS_TOKEN', cardinality=ZeroOrMore)
    roles = RelationshipTo(
        'Role', 'HAS_ROLE', cardinality=ZeroOrMore, show=True)
    externals = RelationshipTo(
        'ExternalAccounts', 'HAS_AUTHORIZATION', cardinality=OneOrMore)


class Token(StructuredNode):
    jti = StringProperty(required=True, unique_index=True)
    token = StringProperty(required=True, unique_index=True)
    token_type = StringProperty()
    creation = DateTimeProperty(required=True)
    expiration = DateTimeProperty()
    last_access = DateTimeProperty()
    IP = StringProperty()
    hostname = StringProperty()
    emitted_for = RelationshipFrom('User', 'HAS_TOKEN', cardinality=ZeroOrOne)


class Role(StructuredNode):
    name = StringProperty(required=True, unique_index=True, show=True)
    description = StringProperty(default='No description', show=True)
    privileged = RelationshipFrom(User, 'HAS_ROLE', cardinality=OneOrMore)


class ExternalAccounts(StructuredNode):
    username = StringProperty(required=True, unique_index=True)
    token = StringProperty(required=True)
    email = StringProperty()
    certificate_cn = StringProperty()
    proxyfile = StringProperty()
    description = StringProperty(default='No description')
    main_user = RelationshipFrom(
        User, 'HAS_AUTHORIZATION', cardinality=OneOrMore)
