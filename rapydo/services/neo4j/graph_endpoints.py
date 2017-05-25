# -*- coding: utf-8 -*-

import re
# from datetime import datetime
# import pytz
from functools import wraps
# from py2neo.error import GraphError
# from py2neo.cypher.error.schema import ConstraintViolation
from rapydo.exceptions import RestApiException
from rapydo.rest.definition import EndpointResource
from rapydo.utils import htmlcodes as hcodes

from rapydo.utils.logs import get_logger
log = get_logger(__name__)

__author__ = "Mattia D'Antonio (m.dantonio@cineca.it)"


class GraphBaseOperations(EndpointResource):

    def initGraph(self):
        self.graph = self.get_service_instance('neo4j')
        self._current_user = self.getLoggedUserInstance()

    @staticmethod
    def getSingleLinkedNode(relation):

        nodes = relation.all()
        if len(nodes) <= 0:
            return None
        return nodes[0]

    def getLoggedUserInstance(self):
        user = self.get_current_user()
        if user is None:
            return None
        try:
            return self.graph.User.nodes.get(email=user.email)
        except self.graph.User.DoesNotExist:
            return None

    def getNode(self, Model, identifier, field='accession'):

        try:
            filter = {field: identifier}
            return Model.nodes.get(**filter)

        except Model.DoesNotExist:
            return None

    # HANDLE INPUT PARAMETERS

    @staticmethod
    def createUniqueIndex(*var):

        separator = "#_#"
        return separator.join(var)

    def read_properties(self, schema, values, checkRequired=True):

        properties = {}
        for field in schema:
            if 'custom' in field:
                if 'islink' in field['custom']:
                    if field['custom']['islink']:
                        continue

            k = field["name"]
            if k in values:
                properties[k] = values[k]

            # this field is missing but required!
            elif checkRequired and field["required"]:
                raise RestApiException(
                    'Missing field: %s' % k,
                    status_code=hcodes.HTTP_BAD_REQUEST)

        return properties

    def update_properties(self, instance, schema, properties):

        for field in schema:
            if 'custom' in field:
                if 'islink' in field['custom']:
                    if field['custom']['islink']:
                        continue
            key = field["name"]
            if key in properties:
                instance.__dict__[key] = properties[key]

    def parseAutocomplete(
            self, properties, key, id_key='value', split_char=None):
        value = properties.get(key, None)

        ids = []

        if value is None:
            return ids

        # Multiple autocomplete
        if type(value) is list:
            for v in value:
                if v is None:
                    return None
                if id_key in v:
                    ids.append(v[id_key])
                else:
                    ids.append(v)
            return ids

        # Single autocomplete
        if id_key in value:
            return [value[id_key]]

        # Command line input
        if split_char is None:
            return [value]

        return value.split(split_char)


def graph_transactions(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            from neomodel import db as transaction

            log.verbose("Neomodel transaction BEGIN")
            transaction.begin()

            out = func(self, *args, **kwargs)

            log.verbose("Neomodel transaction COMMIT")
            transaction.commit()

            return out
        except Exception as e:
            log.verbose("Neomodel transaction ROLLBACK")
            try:
                transaction.rollback()
            except Exception as rollback_exp:
                log.warning(
                    "Exception raised during rollback: %s" % rollback_exp)
            raise e

    return wrapper


def catch_graph_exceptions(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):

        from neomodel.exception import RequiredProperty
        from neomodel.exception import UniqueProperty

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

        # TOFIX: to be specified with new neomodel exceptions
        # except ConstraintViolation as e:
        # except UniqueProperty as e:

    return wrapper
