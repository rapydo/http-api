# -*- coding: utf-8 -*-

import re
import pymodm.connection as mongodb
from pymodm.base.models import TopLevelMongoModel
from functools import wraps
from pymongo.errors import DuplicateKeyError
from restapi.connectors import Connector
from restapi.exceptions import DatabaseDuplicatedEntry, RestApiException
from restapi.utilities.logs import log


def catch_db_exceptions(func):
    @wraps(func)
    def wrapper(*args, **kwargs):

        try:
            return func(*args, **kwargs)

        except DatabaseDuplicatedEntry as e:
            # already catched and parser, raise up
            raise(e)

        except DuplicateKeyError as e:

            regexp = r".+ duplicate key error collection: auth\."
            regexp += r"(.+) index: .+ dup key: { (.+): \"(.+)\" }"
            m = re.search(regexp, str(e))
            if m:
                node = m.group(1)
                prop = m.group(2)
                val = m.group(3)
                error = "A {} already exists with {}: {}".format(node, prop, val)

                raise DatabaseDuplicatedEntry(error)

            log.error("Unrecognized error message: {}", e)
            raise DatabaseDuplicatedEntry("Duplicated entry")

        # except ValidationError as e:
        #     # not handled
        #     raise e
        except RecursionError as e:
            # Got some circular references? Let's try to break them,
            # then try to understand the cause...
            raise RestApiException(str(e), status_code=400)

        except BaseException as e:
            log.critical("Raised unknown exception: {}", type(e))
            raise e

    return wrapper


class MongoExt(Connector):

    def get_connection_exception(self):
        return None

    def preconnect(self, **kwargs):
        return True

    def postconnect(self, obj, **kwargs):
        return True

    def connect(self, **kwargs):

        variables = self.variables
        variables.update(kwargs)

        # connect for authentication if required
        uri = "mongodb://{}:{}/{}".format(
            variables.get('host'),
            variables.get('port'),
            AUTH_DB,
        )
        mongodb.connect(uri, alias=AUTH_DB)

        ##################
        db = variables.get('database', 'UNKNOWN')
        uri = "mongodb://{}:{}/{}".format(
            variables.get('host'),
            variables.get('port'), db
        )

        mongodb.connect(uri, alias=db)
        link = mongodb._get_connection(alias=db)
        log.verbose("Connected to db {}", db)

        class obj:
            connection = link

        TopLevelMongoModel.save = catch_db_exceptions(TopLevelMongoModel.save)
        return obj

    def initialize(self, pinit, pdestroy, abackend=None):
        # recover instance with the parent method
        db = self.get_instance()

        if pdestroy:
            # massive destruction
            client = db.connection.database

            from pymongo import MongoClient

            client = MongoClient(
                self.variables.get('host'),
                int(self.variables.get('port'))
            )

            system_dbs = ['admin', 'local', 'config']
            for db in client.database_names():
                if db not in system_dbs:
                    client.drop_database(db)
                    log.critical("Dropped db '{}'", db)

        # if pinit:
        #     pass

        return db


# class Converter:
#     def __init__(self, mongo_model):
#         self._model = mongo_model

#     @classmethod
#     def recursive_inspect(cls, obj, **kwargs):

#         from bson import ObjectId
#         from datetime import datetime

#         ###############
#         tobehidden = ['_cls', 'password']
#         hide_user = kwargs.get('hide_user', True)
#         if hide_user:
#             tobehidden.append('user')
#         hide_fields = kwargs.get('hide_fields')
#         if hide_fields is not None and isinstance(hide_fields, list):
#             tobehidden += hide_fields

#         ###############
#         if isinstance(obj, dict):

#             for key, value in obj.copy().items():

#                 if key in tobehidden:
#                     obj.pop(key)
#                     continue
#                 elif isinstance(value, datetime):
#                     newvalue = value.timestamp()
#                 elif isinstance(value, ObjectId):
#                     newvalue = str(value)
#                 elif isinstance(value, list):
#                     newvalue = []
#                     for element in value:
#                         newvalue.append(cls.recursive_inspect(element, **kwargs))
#                 else:
#                     newvalue = value

#                 obj[key] = newvalue

#         ###############
#         return obj

#     def asdict(self, *args, **kwargs):
#         return self.recursive_inspect(
#             # src: https://jira.mongodb.org/browse/PYMODM-105
#             dict(self._model.to_son()),
#             **kwargs,
#         )
