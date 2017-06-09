# -*- coding: utf-8 -*-

from pymodm import connect
from rapydo.flask_ext import BaseExtension, get_logger

log = get_logger(__name__)


class MongoExt(BaseExtension):

    _defaultdb = 'test'

    def custom_connection(self, **kwargs):

        if len(kwargs) > 0:
            variables = kwargs
        else:
            variables = self.variables

        db = variables.get('database', self._defaultdb)

        uri = "mongodb://%s:%s/%s" % (
            variables.get('host'), variables.get('port'), db)

        # UHM
        if db == self._defaultdb:
            connect(uri)
        else:
            log.debug("Connected to db %s" % db)
            connect(uri, alias=db)
