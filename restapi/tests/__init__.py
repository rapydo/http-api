# -*- coding: utf-8 -*-

"""
@mattia: why is this file here, and why I see thing copied from the old
tests/__init__.py?
"""

import pytest
import json

# from restapi.confs import DEFAULT_HOST, DEFAULT_PORT, API_URL, AUTH_URL
from restapi.tests.utilities import AUTH_URI
# from restapi.tests.utilities import API_URI
from restapi.rest.response import get_content_from_response
from restapi.services.authentication import BaseAuthentication as ba

from utilities import htmlcodes as hcodes

from utilities.logs import get_logger

log = get_logger(__name__)

# SERVER_URI = 'http://%s:%s' % (DEFAULT_HOST, DEFAULT_PORT)
# API_URI = '%s%s' % (SERVER_URI, API_URL)
# AUTH_URI = '%s%s' % (SERVER_URI, AUTH_URL)


class BaseTests():

    #  COPIED FROM restapi/tests/utilities.py
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
