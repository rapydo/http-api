# -*- coding: utf-8 -*-

"""
Base Models for mongo database.

Docs:
https://pymodm.readthedocs.io
https://docs.mongodb.com/manual/applications/data-models-relationships
"""

from pymodm import fields
from pymodm import MongoModel
from restapi.flask_ext.flask_mongo import AUTH_DB

# from pymongo.write_concern import WriteConcern


####################
# Base Models
class Role(MongoModel):
    name = fields.CharField(primary_key=True)
    description = fields.CharField()

    class Meta:
        # write_concern = WriteConcern(j=True)
        connection_alias = AUTH_DB


class User(MongoModel):
    email = fields.EmailField(primary_key=True)
    uuid = fields.CharField()
    # uuid = fields.UUIDField(default=getUUID())
    name = fields.CharField()
    surname = fields.CharField()
    authmethod = fields.CharField()
    password = fields.CharField(required=True)
    first_login = fields.DateTimeField()
    last_login = fields.DateTimeField()
    last_password_change = fields.DateTimeField()
    is_active = fields.BooleanField(default=True)
    roles = fields.EmbeddedDocumentListField(Role)

    class Meta:
        # write_concern = WriteConcern(j=True)
        connection_alias = AUTH_DB


class Token(MongoModel):
    jti = fields.CharField()
    token = fields.CharField()
    token_type = fields.CharField()
    creation = fields.DateTimeField()
    expiration = fields.DateTimeField()
    last_access = fields.DateTimeField()
    IP = fields.CharField()
    hostname = fields.CharField(blank=True)
    user_id = fields.ReferenceField(User, blank=True)
    # emitted_for = fields.EmbeddedDocumentField(User, blank=True)

    class Meta:
        # write_concern = WriteConcern(j=True)
        connection_alias = AUTH_DB
