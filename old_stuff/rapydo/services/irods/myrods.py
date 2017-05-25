# -*- coding: utf-8 -*-

"""
iRODS connection via Official API.
Python 3 is NOT supported at the moment.

TOFIX: this will be the new default very soon

"""

import os
import irods
from irods.session import iRODSSession
from rapydo.utils.logs import get_logger, silence_loggers

log = get_logger(__name__)
# Silence the irods debugger which adds some useless handler
silence_loggers()


#####################################
# IRODS CLASS
class MyRods(object):
    """ A class to use irods with official python apis"""

    _session = None
    _default_zone = None

    def __init__(self):
        super(MyRods, self).__init__()

        # config
        self._default_zone = os.environ['IRODS_ZONE']
        iconnection = {
            'host': os.environ['RODSERVER_ENV_IRODS_HOST'],
            'user': os.environ['IRODS_USER'],
            'password': os.environ['RODSERVER_ENV_IRODS_PASS'],
            'port': os.environ['RODSERVER_PORT_1247_TCP_PORT'],
            'zone': self._default_zone
        }
        self._session = iRODSSession(**iconnection)
        log.info("Connected to irods")

    def other(self):
        """ To define """
        try:
            coll = self._session.collections.get(
                "/" + self._default_zone)
        except irods.exception.NetworkException as e:
            log.critical("Failed to read irods object:\n%s" % str(e))
            return False

        # log.debug(coll.id)
        # log.debug(coll.path)

        for col in coll.subcollections:
            log.debug("Collection %s" % col)

        for obj in coll.data_objects:
            log.debug("Data obj %s" % obj)

        return self

# mirods = MyRods()
