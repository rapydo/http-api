# -*- coding: utf-8 -*-

"""
@mattia: why is this file here, and why I see thing copied from the old
tests/__init__.py?
"""

import pytest
import json
import string
import random

from restapi.confs import DEFAULT_HOST, DEFAULT_PORT, API_URL, AUTH_URL
from restapi.rest.response import get_content_from_response
from restapi.services.authentication import BaseAuthentication as ba
from utilities import htmlcodes as hcodes

from utilities.logs import get_logger

log = get_logger(__name__)

SERVER_URI = 'http://%s:%s' % (DEFAULT_HOST, DEFAULT_PORT)
API_URI = '%s%s' % (SERVER_URI, API_URL)
AUTH_URI = '%s%s' % (SERVER_URI, AUTH_URL)


class ParsedResponse(object):
    pass


class BaseTests():

    def do_login(self, client, USER, PWD,
                 status_code=hcodes.HTTP_OK_BASIC,
                 error=None, **kwargs):
        """
            Make login and return both token and authorization header
        """

        if USER is None or PWD is None:
            ba.myinit()
            if USER is None:
                USER = ba.default_user
            if PWD is None:
                PWD = ba.default_password

        # AUTH_MAX_LOGIN_ATTEMPTS=0
        # AUTH_REGISTER_FAILED_LOGIN=False

        # AUTH_SECOND_FACTOR_AUTHENTICATION=None

        # AUTH_DISABLE_UNUSED_CREDENTIALS_AFTER=0
        # AUTH_MAX_PASSWORD_VALIDITY=0

        data = {'username': USER, 'password': PWD}
        for v in kwargs:
            data[v] = kwargs[v]

        r = client.post(AUTH_URI + '/login', data=json.dumps(data))

        if r.status_code != hcodes.HTTP_OK_BASIC:
            # VERY IMPORTANT FOR DEBUGGING WHEN ADVANCED AUTH OPTIONS ARE ON
            c = json.loads(r.data.decode('utf-8'))
            log.error(c['Response']['errors'])

        assert r.status_code == status_code

        content = json.loads(r.data.decode('utf-8'))
        if error is not None:
            errors = content['Response']['errors']
            if errors is not None:
                assert errors[0] == error

        token = ''
        if content is not None:
            data = content.get('Response', {}).get('data', {})
            if data is not None:
                token = data.get('token', '')
        return {'Authorization': 'Bearer ' + token}, token

    def save(self, variable, value, read_only=False):
        """
            Save a variable in the class, to be re-used in further tests
            In read_only mode the variable cannot be rewritten
        """
        if hasattr(self.__class__, variable):
            data = getattr(self.__class__, variable)
            if "read_only" in data and data["read_only"]:
                pytest.fail(
                    "Cannot overwrite a read_only variable [%s]" % variable
                )

        data = {'value': value, 'read_only': read_only}
        setattr(self.__class__, variable, data)

    def get(self, variable):
        """
            Retrieve a previously stored variable using the .save method
        """
        if hasattr(self.__class__, variable):
            data = getattr(self.__class__, variable)
            if "value" in data:
                return data["value"]

        raise AttributeError("Class variable %s not found" % variable)
        return None

    def get_content(self, response):
        content, err, meta, code = get_content_from_response(response)

        # Since unittests use class object and not instances
        # This is the only workaround to set a persistent variable:
        # abuse of the __class__ property

        self.__class__.latest_response = {
            "metadata": meta,
            "content": content,
            "errors": err,
            "status": code,
        }
        return content

    def get_celery(self, app):

        from restapi.flask_ext.flask_celery import CeleryExt
        from restapi.services.detect import detector
        celery = detector.extensions_instances.get('celery')
        celery.celery_app.app = app
        CeleryExt.celery_app = celery.celery_app
        return CeleryExt

    def randomString(self, len=16, prefix="TEST:"):
        """
            Create a random string to be used to build data for tests
        """
        if len > 500000:
            lis = list(string.ascii_lowercase)
            return ''.join(random.choice(lis) for _ in range(len))

        rand = random.SystemRandom()
        charset = string.ascii_uppercase + string.digits

        random_string = prefix
        for _ in range(len):
            random_string += rand.choice(charset)

        return random_string

    def parseResponse(self, response, inner=False):
        """
            This method is used to verify and simplify the access to
            json-standard-responses. It returns an Object built
            by mapping json content as attributes.
            This is a recursive method, the inner flag is used to
            distinguish further calls on inner elements.
        """

        if response is None:
            return None

        # OLD RESPONSE, NOT STANDARD-JSON
        if not inner and isinstance(response, dict):
            return response

        data = []

        assert isinstance(response, list)

        for element in response:
            assert isinstance(element, dict)
            assert "id" in element
            assert "type" in element
            assert "attributes" in element
            # # links is optional -> don't test
            assert "links" in element
            # # relationships is optional -> don't test
            assert "relationships" in element

            newelement = ParsedResponse()
            setattr(newelement, "_id", element["id"])
            setattr(newelement, "_type", element["type"])
            if "links" in element:
                setattr(newelement, "_links", element["links"])

            setattr(newelement, "attributes", ParsedResponse())

            for key in element["attributes"]:
                setattr(newelement.attributes, key, element["attributes"][key])

            if "relationships" in element:
                for relationship in element["relationships"]:
                    setattr(newelement, "_" + relationship,
                            self.parseResponse(
                                element["relationships"][relationship],
                                inner=True
                            ))

            data.append(newelement)

        return data

    def checkResponse(self, response, fields, relationships):
        """
        Verify that the response contains the given fields and relationships
        """

        for f in fields:
            if not hasattr(response[0].attributes, f):
                pytest.fail("Missing property: %s" % f)

        for r in relationships:
            if not hasattr(response[0], "_" + r):
                pytest.fail("Missing relationship: %s" % r)
