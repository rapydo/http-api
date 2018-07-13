# -*- coding: utf-8 -*-

import sys
import contextlib
from restapi.flask_ext import BaseExtension, get_logger

log = get_logger(__name__)


########################
class Devnull(object):

    def write(self, _):
        pass

    def flush(self):
        pass


@contextlib.contextmanager
def nostderr():
    """
    Thanks Alex: https://stackoverflow.com/a/1810086
    """
    savestderr = sys.stderr
    sys.stderr = Devnull()
    try:
        yield
    finally:
        sys.stderr = savestderr
########################


class ElasticPythonExt(BaseExtension):

    def custom_connection(self, **kwargs):

        # mix kwargs with variables
        variables = self.variables
        for key, value in kwargs.items():
            variables[key] = value

        from elasticsearch import Elasticsearch

        host = variables.get('host')
        port = variables.get('port')
        obj = Elasticsearch([host], port=port)
        # elhost = "%s:%s" % (variables.get('host'), variables.get('port'))
        # host = {'host': elhost}
        # log.verbose("Connecting to elastic: %s", elhost)
        # obj = Elasticsearch([host])
        with nostderr():
            try:
                check = obj.ping()
            except BaseException:
                check = False

        if check:
            log.debug('Connected to elastic: %s:%s', host, port)
        else:
            msg = 'Failed to connect: %s:%s', host, port
            log.error(msg)
            raise EnvironmentError(msg)

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


def today():
    from datetime import datetime
    return datetime.today().strftime("%Y.%m.%d")


def log_today(elastic, msg=None):
    if msg is None:
        return False
    index = 'log-%s' % today()
    doc = 'logs'
    elastic.index(index=index, doc_type=doc, body=msg)
    return True


def generator(data):
    for element in data.get('hits', []).get('hits', []):
        yield element.get('_source', {})


def get_logs(elastic, day=None):
    if day is None:
        day = today()
    index = 'log-%s' % today()

    # search all
    out = elastic.search(
        index=index, size=10000, body={"query": {'match_all': {}}}
    )
    return generator(out)
