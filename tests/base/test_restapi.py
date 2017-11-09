# -*- coding: utf-8 -*-

"""
Tests for http api base (mostly authentication)
"""


from restapi.tests import BaseTests, API_URI, AUTH_URI
from utilities import htmlcodes as hcodes
from utilities.logs import get_logger

__author__ = "Paolo D'Onorio De Meo (p.donoriodemeo@cineca.it)"
__author__ = "Mattia D'Antonio (m.dantonio@cineca.it)"

log = get_logger(__name__)


class TestApp(BaseTests):

    """
    Unittests perpared for the core basic functionalities.

    - service is alive
    - login/logout
    - profile
    - tokens

    Note: security part should be checked even if it will not be enabled
    """

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

        # TODO: test that a call from a browser receives HTML back
        # from restapi.rest.response import MIMETYPE_HTML
        # r = client.get(endpoint, content_type=MIMETYPE_HTML)
        # output = self.get_content(r)
        # print("TEST", r, output)

        # Check HTML response to status if agent/request is text/html

    def test_02_GET_specifications(self, client):
        """ Test that the flask server is running and reachable """

        # Check success
        endpoint = API_URI + '/specs'
        log.info("*** VERIFY if API specifications are online")
        r = client.get(endpoint)
        assert r.status_code == hcodes.HTTP_OK_BASIC

    def test_03_GET_login(self, client):
        """ Check that you can login and receive back your token """

        log.info("*** VERIFY valid credentials")
        headers, _ = self.do_login(client, None, None)
        self.save("auth_header", headers)

        # Check failure
        log.info("*** VERIFY invalid credentials")

        headers, _ = self.do_login(
            client, 'ABC-Random-User-XYZ', 'ABC-Random-Pass-XYZ',
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

        # CREATING 3 TOKENS
        tokens = []
        num_tokens = 3

        for i in range(num_tokens):
            header, token = self.do_login(client, None, None)
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
        self.save("token_id", str(content.pop(1)["id"]))

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
