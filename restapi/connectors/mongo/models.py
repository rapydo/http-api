"""
Base Models for mongo database.

Docs:
https://pymodm.readthedocs.io
https://docs.mongodb.com/manual/applications/data-models-relationships
"""
import os

from pymodm import MongoModel, fields
from pymongo.operations import IndexModel

# from pymongo.write_concern import WriteConcern
AUTH_DB = os.getenv("MONGO_DATABASE")


####################
# Base Models
class Role(MongoModel):
    name = fields.CharField()
    description = fields.CharField()

    class Meta:
        # write_concern = WriteConcern(j=True)
        connection_alias = AUTH_DB

        indexes = [IndexModel("name", unique=True)]


class User(MongoModel):
    id = fields.CharField(primary_key=True)
    uuid = fields.CharField()
    email = fields.EmailField()
    name = fields.CharField()
    surname = fields.CharField()
    authmethod = fields.CharField()
    password = fields.CharField(required=True)
    mfa_hash = fields.CharField()
    first_login = fields.DateTimeField(blank=True)
    last_login = fields.DateTimeField(blank=True)
    last_password_change = fields.DateTimeField(blank=True)
    is_active = fields.BooleanField(default=True)
    privacy_accepted = fields.BooleanField(default=True)
    expiration = fields.DateTimeField(blank=True)

    roles = fields.EmbeddedDocumentListField(Role, blank=True)
    belongs_to = fields.EmbeddedDocumentField("Group", blank=True)

    class Meta:
        # write_concern = WriteConcern(j=True)
        connection_alias = AUTH_DB

        indexes = [IndexModel("uuid", unique=True), IndexModel("email", unique=True)]


class Token(MongoModel):
    jti = fields.CharField()
    token = fields.CharField()
    token_type = fields.CharField()
    creation = fields.DateTimeField()
    expiration = fields.DateTimeField()
    last_access = fields.DateTimeField()
    IP = fields.CharField()
    # no longer used
    hostname = fields.CharField(blank=True)
    location = fields.CharField(blank=True)
    user_id = fields.ReferenceField(User, blank=True)

    class Meta:
        # write_concern = WriteConcern(j=True)
        connection_alias = AUTH_DB

        indexes = [IndexModel("jti", unique=True), IndexModel("token", unique=True)]


class Group(MongoModel):
    # otherwise will raise this error: Object of type UUID is not JSON serializable
    id = fields.CharField(primary_key=True)
    uuid = fields.CharField()
    shortname = fields.CharField()
    fullname = fields.CharField()

    class Meta:
        # write_concern = WriteConcern(j=True)
        connection_alias = AUTH_DB

        indexes = [
            IndexModel("uuid", unique=True),
            IndexModel("shortname", unique=True),
        ]
