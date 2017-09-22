# -*- coding: utf-8 -*-

"""
Tests for http api base (mostly authentication)
"""

import pytest
import json

# from tests import RestTestsBase
# from restapi.tests.utilities import TestUtilities
from restapi.tests.utilities import API_URI, AUTH_URI
from restapi.services.authentication import BaseAuthentication as ba
from restapi.rest.response import get_content_from_response
from utilities import htmlcodes as hcodes
from utilities.logs import get_logger

__author__ = "Paolo D'Onorio De Meo (p.donoriodemeo@cineca.it)"
__author__ = "Mattia D'Antonio (m.dantonio@cineca.it)"

log = get_logger(__name__)


class TestApp():

    """
    Unittests perpared for the core basic functionalities.

    - service is alive
    - login/logout
    - profile
    - tokens

    Note: security part should be checked even if it will not be enabled
    """

    ############################################################
    ############################################################
    ############################################################
    #  COPIED FROM restapi/tests/utilities.py
    def do_login(self, client, USER, PWD,
                 status_code=hcodes.HTTP_OK_BASIC,
                 error=None, **kwargs):
        """
            Make login and return both token and authorization header
        """

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
    ############################################################
    ############################################################
    ############################################################

    def test_01_GET_status(self, client):
        """ Test that the flask server is running and reachable """

        # Check success
        endpoint = API_URI + '/status'
        log.info("*** VERIFY if API is online")
        r = client.get(endpoint)
        assert r.status_code == hcodes.HTTP_OK_BASIC

        # Check failure
        log.info("*** VERIFY if invalid endpoint gives Not Found")
        r = client.get(API_URI)
        assert r.status_code == hcodes.HTTP_BAD_NOTFOUND

    def test_02_GET_specifications(self, client):
        """ Test that the flask server is running and reachable """

        # Check success
        endpoint = API_URI + '/specs'
        log.info("*** VERIFY if API specifications are online")
        r = client.get(endpoint)
        assert r.status_code == hcodes.HTTP_OK_BASIC

    def test_03_GET_login(self, client):
        """ Check that you can login and receive back your token """

        ba.myinit()
        username = ba.default_user
        password = ba.default_password

        log.info("*** VERIFY valid credentials")
        headers, _ = self.do_login(client, username, password)
        self.save("auth_header", headers)

        # Check failure
        log.info("*** VERIFY invalid credentials")

        headers, _ = self.do_login(
            client, username + 'X', password + 'Y',
            status_code=hcodes.HTTP_BAD_UNAUTHORIZED)

        # this check verifies a BUG with neo4j causing crash of auth module
        # when using a non-email-username to authenticate
        log.info("*** VERIFY with a non-email-username")

        headers, _ = self.do_login(
            client, 'notanemail', '[A-Za-z0-9]+',
            status_code=hcodes.HTTP_BAD_UNAUTHORIZED)

    def test_04_GET_profile(self, client):
        """ Check if you can use your token for protected endpoints """

        endpoint = AUTH_URI + '/profile'

        # Check success
        log.info("*** VERIFY valid token")
        r = client.get(endpoint, headers=self.get("auth_header"))
        assert r.status_code == hcodes.HTTP_OK_BASIC

        # Check failure
        log.info("*** VERIFY invalid token")
        r = client.get(endpoint)
        assert r.status_code == hcodes.HTTP_BAD_UNAUTHORIZED

    def test_05_GET_logout(self, client):
        """ Check that you can logout with a valid token """

        endpoint = AUTH_URI + '/logout'

        # Check success
        log.info("*** VERIFY valid token")
        r = client.get(endpoint, headers=self.get("auth_header"))
        assert r.status_code == hcodes.HTTP_OK_NORESPONSE

        # Check failure
        log.info("*** VERIFY invalid token")
        r = client.get(endpoint)
        assert r.status_code == hcodes.HTTP_BAD_UNAUTHORIZED

    def test_06_GET_tokens(self, client):

        endpoint = AUTH_URI + '/login'
        ba.myinit()
        username = ba.default_user
        password = ba.default_password

        # CREATING 3 TOKENS
        tokens = []
        num_tokens = 3

        for i in range(num_tokens):
            header, token = self.do_login(client, username, password)
            if i == 0:
                self.save("tokens_header", header, read_only=True)
            tokens.append(token)

        endpoint = AUTH_URI + '/tokens'

        # TEST GET ALL TOKENS (expected at least num_tokens)
        r = client.get(endpoint, headers=self.get("tokens_header"))
        content = self.get_content(r)
        assert r.status_code == hcodes.HTTP_OK_BASIC
        assert len(content) >= num_tokens

        # save the second token to be used for further tests
        self.save("token_id", str(content.pop(0)["id"]))

        # TEST GET SINGLE TOKEN
        endpoint_single = "%s/%s" % (endpoint, self.get("token_id"))
        r = client.get(endpoint_single, headers=self.get("tokens_header"))
        assert r.status_code == hcodes.HTTP_OK_BASIC

        # TEST GET INVALID SINGLE TOKEN
        r = client.get(endpoint + "/0", headers=self.get("tokens_header"))
        assert r.status_code == hcodes.HTTP_BAD_NOTFOUND

    def test_07_DELETE_tokens(self, client):

        endpoint = AUTH_URI + '/tokens'
        endpoint_single = "%s/%s" % (endpoint, self.get("token_id"))

        # TEST DELETE OF A SINGLE TOKEN
        r = client.delete(endpoint_single, headers=self.get("tokens_header"))
        assert r.status_code == hcodes.HTTP_OK_NORESPONSE

        # TEST AN ALREADY DELETED TOKEN
        r = client.delete(endpoint_single, headers=self.get("tokens_header"))
        assert r.status_code == hcodes.HTTP_BAD_UNAUTHORIZED

        # TEST INVALID DELETE OF A SINGLE TOKEN
        r = client.delete(endpoint + "/0", headers=self.get("tokens_header"))
        assert r.status_code == hcodes.HTTP_BAD_UNAUTHORIZED

        # TEST DELETE OF ALL TOKENS
        r = client.delete(endpoint, headers=self.get("tokens_header"))
        assert r.status_code == hcodes.HTTP_OK_NORESPONSE

        # TEST TOKEN IS NOW INVALID
        r = client.get(endpoint, headers=self.get("tokens_header"))
        assert r.status_code == hcodes.HTTP_BAD_UNAUTHORIZED
