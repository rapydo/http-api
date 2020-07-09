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
    # To be enabled after completed the output serialization,
    # otherwise will raise this error: Object of type UUID is not JSON serializable
    # uuid = fields.UUIDField()
    id = fields.CharField(primary_key=True)
    uuid = fields.CharField()
    email = fields.EmailField()
    name = fields.CharField()
    surname = fields.CharField()
    authmethod = fields.CharField()
    password = fields.CharField(required=True)
    first_login = fields.DateTimeField()
    last_login = fields.DateTimeField()
    last_password_change = fields.DateTimeField()
    is_active = fields.BooleanField(default=True)
    privacy_accepted = fields.BooleanField(default=True)
    roles = fields.EmbeddedDocumentListField(Role, blank=True)

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

        indexes = [IndexModel("token", unique=True)]
