# -*- coding: utf-8 -*-

import pymodm.connection as mongodb
from restapi.flask_ext import BaseExtension, get_logger

log = get_logger(__name__)

AUTH_DB = 'auth'


class MongoExt(BaseExtension):

    # _defaultdb = 'test'
    # _authdb = 'auth'
    # _defaultdb = 'auth'

    def custom_connection(self, **kwargs):

        ##################
        # mix kwargs with variables
        variables = self.variables
        for key, value in kwargs.items():
            variables[key] = value
        # log.pp(variables)

        ##################
        # connect for authentication if required
        uri = "mongodb://%s:%s/%s" % (
            variables.get('host'), variables.get('port'), AUTH_DB)
        mongodb.connect(uri, alias=AUTH_DB)

        ##################
        db = variables.get('database', 'UNKNOWN')
        uri = "mongodb://%s:%s/%s" % (
            variables.get('host'), variables.get('port'), db)

        mongodb.connect(uri, alias=db)
        link = mongodb._get_connection(alias=db)
        log.very_verbose("Connected to db %s", db)

        class obj:
            connection = link

        return obj

    def custom_init(self, pinit=False, pdestroy=False, **kwargs):
        """ Note: we ignore args here """

        # recover instance with the parent method
        db = super().custom_init()

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
                    log.critical("Dropped db '%s'", db)

        # if pinit:
        #     pass

        return db
