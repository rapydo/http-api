# -*- coding: utf-8 -*-

import re
from functools import wraps
from restapi.exceptions import RestApiException
from restapi.rest.definition import EndpointResource
from utilities import htmlcodes as hcodes

from utilities.logs import get_logger
log = get_logger(__name__)

__author__ = "Mattia D'Antonio (m.dantonio@cineca.it)"


class GraphBaseOperations(EndpointResource):

    def initGraph(self):
        log.warning(
            "This method is deprecated, use get_service_instance and " +
            "get_current_user instead")
        self.graph = self.get_service_instance('neo4j')
        self._current_user = self.get_current_user()

    @staticmethod
    def getSingleLinkedNode(relation):

        nodes = relation.all()
        if len(nodes) <= 0:
            return None
        return nodes[0]

    def getNode(self, Model, identifier, field='accession'):

        log.warning(
            "This method is deprecated. use Model.get_or_none() instead")

        try:
            filter = {field: identifier}
            return Model.nodes.get(**filter)

        except Model.DoesNotExist:
            return None

    @staticmethod
    def createUniqueIndex(*var):

        separator = "#_#"
        return separator.join(var)


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
                log.warning("Exception raised during rollback: %s", sub_ex)
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
            except SystemError as e:
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
                    log.warning("Exception raised during rollback: %s", sub_ex)
            raise e

    return wrapper

def catch_graph_exceptions(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):

        from neomodel.exceptions import RequiredProperty
        from neomodel.exceptions import UniqueProperty

        try:
            return func(self, *args, **kwargs)

        except (UniqueProperty) as e:

            prefix = "Node [0-9]+ already exists with label"
            regExpr = "%s (.+) and property (.+)" % prefix
            m = re.search(regExpr, str(e))
            if m:
                node = m.group(1)
                prop = m.group(2)
                error = "A %s already exist with %s" % (node, prop)
            else:
                error = str(e)

            raise RestApiException(
                error,
                status_code=hcodes.HTTP_BAD_CONFLICT
            )
        except (RequiredProperty) as e:
            raise RestApiException(str(e))

        # FIXME: to be specified with new neomodel exceptions
        # except ConstraintViolation as e:
        # except UniqueProperty as e:

    return wrapper
