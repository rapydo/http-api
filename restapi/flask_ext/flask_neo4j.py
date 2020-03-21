# -*- coding: utf-8 -*-

""" Neo4j GraphDB flask connector """

import re
from functools import wraps
from neomodel import db, config
from restapi.flask_ext import BaseExtension
from restapi.utilities.logs import log


class NeomodelClient:
    def __init__(self, db):
        self.db = db

    def refresh_connection(self):
        if self.db.url is None:
            log.critical("Unable to refresh neo4j connection")
            return False

        log.info("Refreshing neo4j connection...")
        self.db.set_connection(self.db.url)
        return True

    def cypher(self, query):
        """ Execute normal neo4j queries """
        try:
            # results, meta = db.cypher_query(query)
            results, _ = db.cypher_query(query)
        except Exception as e:
            raise Exception(
                "Failed to execute Cypher Query: {}\n{}".format(query, e))
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

    def sanitize_input(self, term):
        '''
        Strip and clean up term from special characters.
        '''
        return term.strip().replace("*", "").replace("'", "\\'").replace("~", "")

    def fuzzy_tokenize(self, term):
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


class NeoModel(BaseExtension):
    def set_connection_exception(self):

        try:
            # neomodel 3.3.1-
            import socket
            import neo4j

            return (
                socket.gaierror,
                neo4j.bolt.connection.ServiceUnavailable,  # neo4j 3.2+
                neo4j.exceptions.ServiceUnavailable,  # neo4j 3.2.2+
            )
        except AttributeError:
            # neomodel 3.3.2
            from neobolt.addressing import AddressError
            from neobolt.exceptions import ServiceUnavailable

            return (ServiceUnavailable, AddressError)

    def custom_connection(self, **kwargs):

        if len(kwargs) > 0:
            variables = kwargs
        else:
            variables = self.variables

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

    def custom_init(self, pinit=False, pdestroy=False, abackend=None, **kwargs):
        """ Note: we ignore args here """

        # recover instance with the parent method
        graph = super().custom_init()

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
        from neomodel import db as transaction

        try:

            transaction.begin()
            log.verbose("Neomodel transaction BEGIN")

            out = func(self, *args, **kwargs)

            transaction.commit()
            log.verbose("Neomodel transaction COMMIT")

            return out
        except Exception as e:
            log.verbose("Neomodel transaction ROLLBACK")
            try:
                transaction.rollback()
            except Exception as sub_ex:
                log.warning("Exception raised during rollback: {}", sub_ex)
            raise e

    return wrapper


def graph_nestable_transactions(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        from neomodel import db as transaction

        transaction_open = True
        try:

            try:
                transaction.begin()
                log.verbose("Neomodel transaction BEGIN2")
            except SystemError:
                transaction_open = False
                log.debug("Neomodel transaction is already in progress")

            out = func(self, *args, **kwargs)

            if transaction_open:
                transaction.commit()
                log.verbose("Neomodel transaction COMMIT2")
            else:
                log.debug("Skipping neomodel transaction commit")

            return out
        except Exception as e:
            if not transaction_open:
                log.debug("Skipping neomodel transaction rollback")
            else:
                try:
                    log.verbose("Neomodel transaction ROLLBACK")
                    transaction.rollback()
                except Exception as sub_ex:
                    log.warning("Exception raised during rollback: {}", sub_ex)
            raise e

    return wrapper
