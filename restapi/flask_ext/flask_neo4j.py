# -*- coding: utf-8 -*-

""" Neo4j GraphDB flask connector """

import socket
import neo4j
from neomodel import db, config
from restapi.flask_ext import BaseExtension, get_logger
from utilities.logs import re_obscure_pattern

log = get_logger(__name__)


class NeomodelClient():

    def __init__(self, db):
        self.db = db

    def cypher(self, query):
        """ Execute normal neo4j queries """
        try:
            # results, meta = db.cypher_query(query)
            results, _ = db.cypher_query(query)
        except Exception as e:
            raise Exception(
                "Failed to execute Cypher Query: %s\n%s" % (query, str(e)))
        # log.debug("Graph query.\nResults: %s\nMeta: %s", results, meta)
        return results


class NeoModel(BaseExtension):

    def set_connection_exception(self):
        return (
            socket.gaierror,
            neo4j.bolt.connection.ServiceUnavailable,  # neo4j 3.2+
            neo4j.exceptions.ServiceUnavailable  # neo4j 3.2.2+
        )

    def custom_connection(self, **kwargs):

        if len(kwargs) > 0:
            variables = kwargs
        else:
            variables = self.variables

        self.uri = "bolt://%s:%s@%s:%s" % \
            (
                # User:Password
                variables.get('user', 'neo4j'),
                variables.get('password'),
                # Host:Port
                variables.get('host'),
                variables.get('port'),
            )
        log.very_verbose("URI IS %s" % re_obscure_pattern(self.uri))

        config.DATABASE_URL = self.uri
        # Ensure all DateTimes are provided with a timezone
        # before being serialised to UTC epoch
        config.FORCE_TIMEZONE = True  # default False
        db.url = self.uri
        db.set_connection(self.uri)

        client = NeomodelClient(db)
        return client

        # return db
