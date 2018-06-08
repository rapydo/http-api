# -*- coding: utf-8 -*-

import pymodm.connection as mongodb
from restapi.flask_ext import BaseExtension, get_logger

log = get_logger(__name__)


class ElasticPythonExt(BaseExtension):

    def custom_connection(self, **kwargs):

        # mix kwargs with variables
        variables = self.variables
        for key, value in kwargs.items():
            variables[key] = value

        from elasticsearch import Elasticsearch
        host = {
            'host': "%s:%s" % (variables.get('host'), variables.get('port')),
            # 'port': 443, 'url_prefix': 'es', 'use_ssl': True
        }
        obj = Elasticsearch([host])
        return obj

    # def custom_init(self, pinit=False, pdestroy=False, **kwargs):
    #     """ Note: we ignore args here """

    #     # recover instance with the parent method
    #     db = super().custom_init()

    #     if pdestroy:
    #         # massive destruction
    #         client = db.connection.database

    #         from pymongo import MongoClient
    #         client = MongoClient(
    #             self.variables.get('host'),
    #             int(self.variables.get('port'))
    #         )

    #         system_dbs = ['admin', 'local']
    #         for db in client.database_names():
    #             if db not in system_dbs:
    #                 client.drop_database(db)
    #                 log.critical("Dropped db '%s'", db)

    #     if pinit:
    #         # TODO: discuss!
    #         # needed from EPOS use case
    #         pass

    #     return db

# ElasticInjector
