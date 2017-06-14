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
