# -*- coding: utf-8 -*-

import pymodm.connection as mongodb
from rapydo.flask_ext import BaseExtension, get_logger

log = get_logger(__name__)


class MongoExt(BaseExtension):

    # _defaultdb = 'test'
    _defaultdb = 'auth'

    def custom_connection(self, **kwargs):

        if len(kwargs) > 0:
            variables = kwargs
        else:
            variables = self.variables

        db = variables.get('database', self._defaultdb)

        uri = "mongodb://%s:%s/%s" % (
            variables.get('host'), variables.get('port'), db)

        # if db == self._defaultdb:
        #     mongodb.connect(uri)
        #     obj = mongodb._get_connection()
        # else:

        mongodb.connect(uri, alias=db)
        link = mongodb._get_connection(alias=db)
        log.debug("Connected to db %s" % db)

        class obj:
            connection = link

        return obj

    def custom_init(self, pinit=False, pdestroy=False, **kwargs):
        """ Note: we ignore args here """

        # recover instance with the parent method
        db = super().custom_init()

        if pinit:
            # TODO: discuss!
            # needed from EPOS use case
            pass

        if pdestroy:
            # massive destruction
            client = db.connection.database

            from pymongo import MongoClient
            client = MongoClient(
                self.variables.get('host'),
                int(self.variables.get('port'))
            )

            system_dbs = ['admin', 'local']
            for db in client.database_names():
                if db not in system_dbs:
                    client.drop_database(db)
                    log.critical("Dropped db '%s'" % db)

        return db
