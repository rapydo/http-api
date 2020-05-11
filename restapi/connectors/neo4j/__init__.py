# -*- coding: utf-8 -*-

""" Neo4j GraphDB flask connector """

import re
from functools import wraps
from neomodel import db, config
from neomodel import StructuredNode
from neomodel.match import NodeSet
from neomodel.exceptions import UniqueProperty, DeflateError, DoesNotExist
from neo4j.exceptions import ServiceUnavailable
from neobolt.exceptions import CypherSyntaxError
from neobolt.addressing import AddressError as neobolt_AddressError
from neobolt.exceptions import ServiceUnavailable as neobolt_ServiceUnavailable
from neobolt.exceptions import AuthError as neobolt_AuthError
from restapi.connectors import Connector
from restapi.exceptions import DatabaseDuplicatedEntry
from restapi.utilities.logs import log


def catch_db_exceptions(func):
    @wraps(func)
    def wrapper(*args, **kwargs):

        try:
            return func(*args, **kwargs)
        except DatabaseDuplicatedEntry as e:
            # already catched and parser, raise up
            raise(e)
        except DoesNotExist as e:
            raise (e)
        except CypherSyntaxError as e:
            raise (e)
        except UniqueProperty as e:

            t = "already exists with label"
            m = re.search(
                r"Node\([0-9]+\) {} `(.+)` and property `(.+)` = '(.+)'".format(t),
                str(e)
            )

            if m:
                node = m.group(1)
                prop = m.group(2)
                val = m.group(3)
                error = "A {} already exists with {} = {}".format(node, prop, val)
                raise DatabaseDuplicatedEntry(error)

            log.error("Unrecognized error message: {}", e)  # pragma: no cover
            raise DatabaseDuplicatedEntry("Duplicated entry")  # pragma: no cover
        except DeflateError as e:
            log.warning(e)
            return None

        except ServiceUnavailable as e:  # pragma: no cover
            # refresh_connection()
            raise e

        except Exception as e:  # pragma: no cover
            log.critical("Raised unknown exception: {}", type(e))
            raise e

    return wrapper


class NeomodelClient:
    def __init__(self, db):
        self.db = db
        StructuredNode.save = catch_db_exceptions(StructuredNode.save)
        NodeSet.get = catch_db_exceptions(NodeSet.get)

    def refresh_connection(self):
        if self.db.url is None:
            log.critical("Unable to refresh neo4j connection")
            return False

        log.info("Refreshing neo4j connection...")
        self.db.set_connection(self.db.url)
        return True

    @catch_db_exceptions
    def cypher(query):
        """ Execute normal neo4j queries """
        try:
            # results, meta = db.cypher_query(query)
            results, _ = db.cypher_query(query)
        except CypherSyntaxError as e:
            log.warning(query)
            log.error("Failed to execute Cypher Query\n{}".format(e))
            raise CypherSyntaxError("Failed to execute Cypher Query")
        return results

    @staticmethod
    def getSingleLinkedNode(relation):

        nodes = relation.all()
        if len(nodes) <= 0:
            return None
        return nodes[0]

    @staticmethod
    def createUniqueIndex(*var):

        separator = "#_#"
        return separator.join(var)

    @staticmethod
    def sanitize_input(term):
        '''
        Strip and clean up term from special characters.
        '''
        return term.strip().replace("*", "").replace("'", "\\'").replace("~", "")

    @staticmethod
    def fuzzy_tokenize(term):
        tokens = re.findall(r'[^"\s]\S*|".+?"', term)
        for index, t in enumerate(tokens):

            # Do not apply fuzzy search to quoted strings
            if '"' in t:
                continue

            # Do not apply fuzzy search to special characters
            if t == '+' or t == '!':
                continue

            # Do not apply fuzzy search to special operators
            if t == 'AND' or t == 'OR' or t == 'NOT':
                continue

            tokens[index] += "~1"

        return ' '.join(tokens)


class NeoModel(Connector):

    def get_connection_exception(self):

        # from neomodel 3.3.2
        return (
            neobolt_ServiceUnavailable,
            neobolt_AddressError,
            neobolt_AuthError
        )

    def preconnect(self, **kwargs):
        return True

    def postconnect(self, obj, **kwargs):
        return True

    def connect(self, **kwargs):

        variables = kwargs or self.variables

        self.uri = "bolt://{}:{}@{}:{}".format(
            # User:Password
            variables.get('user', 'neo4j'),
            variables.get('password'),
            # Host:Port
            variables.get('host'),
            variables.get('port'),
        )
        config.DATABASE_URL = self.uri
        # Ensure all DateTimes are provided with a timezone
        # before being serialised to UTC epoch
        config.FORCE_TIMEZONE = True  # default False
        db.url = self.uri
        db.set_connection(self.uri)

        client = NeomodelClient(db)
        return client

        # return db

    def initialize(self, pinit, pdestroy, abackend=None):

        # recover instance with the parent method
        graph = self.get_instance()

        # db.init_app(self.app)

        with self.app.app_context():

            if pdestroy:
                log.critical("Destroy current Neo4j data")
                from neomodel import clear_neo4j_database

                clear_neo4j_database(graph.db)

            if pinit:

                auto_index = self.variables.get("autoindexing", 'True') == 'True'

                if auto_index:
                    try:
                        from neomodel import remove_all_labels, install_all_labels
                        remove_all_labels()
                        install_all_labels()
                    except BaseException as e:
                        log.exit(str(e))

        return graph


def graph_transactions(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):

        try:

            db.begin()
            log.verbose("Neomodel transaction BEGIN")

            out = func(self, *args, **kwargs)

            db.commit()
            log.verbose("Neomodel transaction COMMIT")

            return out
        except Exception as e:
            log.verbose("Neomodel transaction ROLLBACK")
            try:
                db.rollback()
            except Exception as sub_ex:
                log.warning("Exception raised during rollback: {}", sub_ex)
            raise e

    return wrapper
