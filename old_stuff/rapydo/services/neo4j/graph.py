# -*- coding: utf-8 -*-

""" Graph DB abstraction from neo4j server """

import os
from rapydo.utils.logs import get_logger
from rapydo.services import ServiceFarm, ServiceObject

log = get_logger(__name__)

###############################
# Verify Graph existence

# Default values, will be overwritten if i find some envs
PROTOCOL = 'http'
HOST = 'agraphdb'
PORT = '7474'
USER = 'neo4j'
PW = USER

try:

    # TOFIX: should we make a function for this docker variables splits?
    HOST = os.environ['GDB_NAME'].split('/').pop()
    PORT = os.environ['GDB_PORT_7474_TCP_PORT'].split(':').pop()
    USER, PW = os.environ['GDB_ENV_NEO4J_AUTH'].split('/')
except Exception as e:
    log.critical(
        "Graph database not found in environment. Check variable GDB_NAME")
    # raise e
    exit(1)


#######################
# GRAPHDB main object
########################

class MyGraph(ServiceObject):
    """" A graph db neo4j instance """

    def __init__(self):
        super(MyGraph, self).__init__()
        self.connect()

    def connect(self):
        """ Connection http descriptor """
        try:
            # os.environ["NEO4J_REST_URL"] = \
            #     PROTOCOL + "://" + USER + ":" + PW + "@" + \
            #     HOST + ":" + PORT + "/db/data"

            # os.environ["NEO4J_BOLT_URL"] = "bolt://%s:%s@%s" % \
            #     (USER, PW, HOST)

            from neomodel import config
            config.DATABASE_URL = "bolt://%s:%s@%s" % \
                (USER, PW, HOST)

            # Ensure all DateTimes are provided with a timezone
            # before being serialised to UTC epoch
            config.FORCE_TIMEZONE = True  # default False
            log.debug("Neo4j connection socket is set")
        except:
            raise EnvironmentError("Missing URL to connect to graph")
        # Set debug for cypher queries
        os.environ["NEOMODEL_CYPHER_DEBUG"] = "1"

    def cypher(self, query):
        """ Execute normal neo4j queries """
        from neomodel import db
        try:
            results, meta = db.cypher_query(query)
        except Exception as e:
            raise Exception(
                "Failed to execute Cypher Query: %s\n%s" % (query, str(e)))
            return False
        # log.debug("Graph query.\nResults: %s\nMeta: %s" % (results, meta))
        return results

    def clean_pending_tokens(self):
        log.debug("Removing all pending tokens")
        return self.cypher("MATCH (a:Token) WHERE NOT (a)<-[]-() DELETE a")

    def clean_all(self):
        # NOTE: now neomodel has a utility function to
        # deletes all nodes and relationships: clear_neo4j_database(db)
        # described here: http://neomodel.readthedocs.io/en/latest/cypher.html
        log.warning("Removing all data")
        return self.cypher("MATCH (n) OPTIONAL MATCH (n)-[r]-() DELETE n,r")


#######################
# Farm to get Graph instances
########################

class GraphFarm(ServiceFarm):

    """ Making some Graphs """

    _graph = None

    @staticmethod
    def define_service_name():
        return 'neo4j'

    def init_connection(self, app):

        # CHECK 1: test the environment
        self._graph = MyGraph()
        log.debug("Neo4j service seems plugged")

        # CHECK 2: test the models
        # Do not import neomodel before the first check
        # 'cos it will force the system to check for connection
        from neomodel import StructuredNode, StringProperty

        class TestConnection(StructuredNode):
            name = StringProperty(unique_index=True)

        log.debug("neomodel: checked labeling on active connection")

    @classmethod
    def get_instance(cls, models2skip=[], use_models=True):

        if GraphFarm._graph is None:
            GraphFarm._graph = MyGraph()
            if use_models:
                cls.load_models()
                # Remove the ones which developers do not want
                models = set(list(cls._models.values())) - set(models2skip)
                GraphFarm._graph.inject_models(models)

        return GraphFarm._graph
