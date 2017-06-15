# -*- coding: utf-8 -*-

"""
Tests for http api base
(mostly authentication)
"""

from tests import RestTestsBase
from rapydo.tests.utilities import TestUtilities
from rapydo.utils.logs import get_logger

__author__ = "Paolo D'Onorio De Meo (p.donoriodemeo@cineca.it)"
log = get_logger(__name__)


class BaseTests(RestTestsBase, TestUtilities):

    """
    Unittests perpared for the core basic functionalities.

    - service is alive
    - login/logout
    - profile
    - tokens

    Note: security part should be checked even if it will not be enabled

    """

    def test_00_NO_TEST(self):
        pass

    def test_01_GET_status(self):
        """ Test that the flask server is running and reachable """

        # Check success
        endpoint = self._api_uri + '/status'
        log.info("*** VERIFY if API is online")
        r = self.app.get(endpoint)
        self.assertEqual(r.status_code, self._hcodes.HTTP_OK_BASIC)

        # Check failure
        log.info("*** VERIFY if invalid endpoint gives Not Found")
        r = self.app.get(self._api_uri)
        self.assertEqual(r.status_code, self._hcodes.HTTP_BAD_NOTFOUND)

    def test_02_GET_specifications(self):
        """ Test that the flask server is running and reachable """

        # Check success
        endpoint = self._api_uri + '/specs'
        log.info("*** VERIFY if API specifications are online")
        r = self.app.get(endpoint)
        self.assertEqual(r.status_code, self._hcodes.HTTP_OK_BASIC)

    def test_03_GET_login(self):
        """ Check that you can login and receive back your token """

        log.info("*** VERIFY valid credentials")
        headers, _ = self.do_login(self._username, self._password)
        self.save("auth_header", headers)

        # Check failure
        log.info("*** VERIFY invalid credentials")

        headers, _ = self.do_login(
            self._username + 'X', self._password + 'Y',
            status_code=self._hcodes.HTTP_BAD_UNAUTHORIZED)

    def test_04_GET_profile(self):
        """ Check if you can use your token for protected endpoints """

        endpoint = self._auth_uri + '/profile'

        # Check success
        log.info("*** VERIFY valid token")
        r = self.app.get(endpoint, headers=self.get("auth_header"))
        self.assertEqual(r.status_code, self._hcodes.HTTP_OK_BASIC)

        # Check failure
        log.info("*** VERIFY invalid token")
        r = self.app.get(endpoint)
        self.assertEqual(r.status_code, self._hcodes.HTTP_BAD_UNAUTHORIZED)

    def test_05_GET_logout(self):
        """ Check that you can logout with a valid token """

        endpoint = self._auth_uri + '/logout'

        # Check success
        log.info("*** VERIFY valid token")
        r = self.app.get(endpoint, headers=self.get("auth_header"))
        self.assertEqual(r.status_code, self._hcodes.HTTP_OK_NORESPONSE)

        # Check failure
        log.info("*** VERIFY invalid token")
        r = self.app.get(endpoint)
        self.assertEqual(r.status_code, self._hcodes.HTTP_BAD_UNAUTHORIZED)

    def test_06_GET_tokens(self):

        endpoint = self._auth_uri + '/login'

        # CREATING 3 TOKENS
        tokens = []
        num_tokens = 3

        for i in range(num_tokens):
            header, token = self.do_login(self._username, self._password)
            if i == 0:
                self.save("tokens_header", header, read_only=True)
            tokens.append(token)

        endpoint = self._auth_uri + '/tokens'

        # TEST GET ALL TOKENS (expected at least num_tokens)
        r = self.app.get(endpoint, headers=self.get("tokens_header"))
        content = self.get_content(r)
        self.assertEqual(r.status_code, self._hcodes.HTTP_OK_BASIC)
        self.assertGreaterEqual(len(content), num_tokens)

        # save the second token to be used for further tests
        self.save("token_id", str(content.pop(1)["id"]))

        # TEST GET SINGLE TOKEN
        endpoint_single = "%s/%s" % (endpoint, self.get("token_id"))
        r = self.app.get(endpoint_single, headers=self.get("tokens_header"))
        self.assertEqual(r.status_code, self._hcodes.HTTP_OK_BASIC)

        # TEST GET INVALID SINGLE TOKEN
        r = self.app.get(endpoint + "/0", headers=self.get("tokens_header"))
        self.assertEqual(r.status_code, self._hcodes.HTTP_BAD_NOTFOUND)

    def test_07_DELETE_tokens(self):

        endpoint = self._auth_uri + '/tokens'
        endpoint_single = "%s/%s" % (endpoint, self.get("token_id"))

        # TEST DELETE OF A SINGLE TOKEN
        r = self.app.delete(endpoint_single, headers=self.get("tokens_header"))
        self.assertEqual(r.status_code, self._hcodes.HTTP_OK_NORESPONSE)

        # TEST AN ALREADY DELETED TOKEN
        r = self.app.delete(endpoint_single, headers=self.get("tokens_header"))
        self.assertEqual(r.status_code, self._hcodes.HTTP_BAD_UNAUTHORIZED)

        # TEST INVALID DELETE OF A SINGLE TOKEN
        r = self.app.delete(endpoint + "/0", headers=self.get("tokens_header"))
        self.assertEqual(r.status_code, self._hcodes.HTTP_BAD_UNAUTHORIZED)

        # TEST DELETE OF ALL TOKENS
        r = self.app.delete(endpoint, headers=self.get("tokens_header"))
        self.assertEqual(r.status_code, self._hcodes.HTTP_OK_NORESPONSE)

        # TEST TOKEN IS NOW INVALID
        r = self.app.get(endpoint, headers=self.get("tokens_header"))
        self.assertEqual(r.status_code, self._hcodes.HTTP_BAD_UNAUTHORIZED)
