# -*- coding: utf-8 -*-

"""
Base Models for mongo database.

See
https://pymodm.readthedocs.io/en/stable/api/index.html
    #pymodm.base.fields.MongoBaseField
And
https://docs.mongodb.com/manual/applications/data-models-relationships
"""

from pymongo.write_concern import WriteConcern
from pymodm import MongoModel, fields


# ####################
# # Templates
# FIXME: inheritance? Not working at the moment
# class AuthModel(MongoModel):

#     class Meta:
#         write_concern = WriteConcern(j=True)
#         connection_alias = 'auth'


# class AuthModelWithUuid(AuthModel):

#     uuid = fields.UUIDField()


####################
# Base Models
class Role(MongoModel):
    name = fields.CharField(primary_key=True)
    description = fields.CharField()

    class Meta:
        write_concern = WriteConcern(j=True)
        connection_alias = 'auth'


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
    roles = fields.EmbeddedDocumentListField(Role)

    class Meta:
        write_concern = WriteConcern(j=True)
        connection_alias = 'auth'


class Token(MongoModel):
    jti = fields.CharField()
    token = fields.CharField()
    creation = fields.DateTimeField()
    expiration = fields.DateTimeField()
    last_access = fields.DateTimeField()
    IP = fields.CharField()
    hostname = fields.CharField(blank=True)
    user_id = fields.ReferenceField(User, blank=True)
    # emitted_for = fields.EmbeddedDocumentField(User, blank=True)

    class Meta:
        write_concern = WriteConcern(j=True)
        connection_alias = 'auth'


class ExternalAccounts(MongoModel):
    username = fields.CharField(primary_key=True)
    token = fields.CharField()
    token_expiration = fields.DateTimeField()
    email = fields.EmailField()
    certificate_cn = fields.CharField()
    certificate_dn = fields.CharField()
    proxyfile = fields.CharField()
    description = fields.CharField(blank=True)
    user_id = fields.ReferenceField(User)
    # NOTE: in the pre-production release we allow only 1 ext_account per user
    # FIXME: probably using user_id instead of main_user
    main_user = fields.EmbeddedDocumentField(User)

    class Meta:
        write_concern = WriteConcern(j=True)
        connection_alias = 'auth'
