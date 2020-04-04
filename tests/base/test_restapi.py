# -*- coding: utf-8 -*-

"""
Tests for http api base (mostly authentication)
"""


from restapi.tests import BaseTests, API_URI, AUTH_URI, BaseAuthentication
from restapi.utilities.htmlcodes import hcodes
from restapi.utilities.logs import log


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
        alive_message = "Server is alive"

        log.info("*** VERIFY if API is online")
        r = client.get(endpoint)
        assert r.status_code == hcodes.HTTP_OK_BASIC
        output = self.get_content(r)
        assert output == alive_message

        # Check failure
        log.info("*** VERIFY if invalid endpoint gives Not Found")
        r = client.get(API_URI)
        assert r.status_code == hcodes.HTTP_BAD_NOTFOUND

        # Check HTML response to status if agent/request is text/html
        headers = {"Accept": 'text/html'}
        r = client.get(endpoint, headers=headers)
        assert r.status_code == hcodes.HTTP_OK_BASIC
        output = r.data.decode('utf-8')
        assert output != alive_message
        assert alive_message in output
        assert "<html" in output
        assert "<body>" in output

    def test_02_GET_specifications(self, client):
        """ Test that the flask server expose swagger specs """

        specs = self.get_specs(client)

        assert "basePath" in specs
        assert "consumes" in specs
        assert "produces" in specs
        assert "application/json" in specs["consumes"]
        assert "application/json" in specs["produces"]
        assert "definitions" in specs
        assert "host" in specs
        assert "info" in specs
        assert "schemes" in specs
        assert "swagger" in specs
        assert "tags" in specs
        assert "security" in specs
        assert "Bearer" in specs["security"][0]
        assert "securityDefinitions" in specs
        assert "Bearer" in specs["securityDefinitions"]
        assert "paths" in specs
        assert "/auth/login" in specs["paths"]
        assert "get" not in specs["paths"]["/auth/login"]
        assert "post" in specs["paths"]["/auth/login"]
        assert "put" not in specs["paths"]["/auth/login"]
        assert "delete" not in specs["paths"]["/auth/login"]

    def test_03_GET_login(self, client):
        """ Check that you can login and receive back your token """

        log.info("*** VERIFY CASE INSENSITIVE LOGIN")
        BaseAuthentication.myinit()
        USER = BaseAuthentication.default_user
        PWD = BaseAuthentication.default_password
        self.do_login(client, USER.upper(), PWD)

        # Off course PWD cannot be upper :D
        self.do_login(
            client, USER, PWD.upper(), status_code=hcodes.HTTP_BAD_UNAUTHORIZED
        )

        log.info("*** VERIFY valid credentials")
        headers, _ = self.do_login(client, None, None)
        self.save("auth_header", headers)

        # Check failure
        log.info("*** VERIFY invalid credentials")

        self.do_login(
            client,
            'ABC-Random-User-XYZ',
            'ABC-Random-Pass-XYZ',
            status_code=hcodes.HTTP_BAD_UNAUTHORIZED,
        )

        # this check verifies a BUG with neo4j causing crash of auth module
        # when using a non-email-username to authenticate
        log.info("*** VERIFY with a non-email-username")

        self.do_login(
            client,
            'notanemail',
            '[A-Za-z0-9]+',
            status_code=hcodes.HTTP_BAD_UNAUTHORIZED,
        )

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
        first_token = None
        num_tokens = 3

        for i in range(num_tokens):
            header, token = self.do_login(client, None, None)
            if i == 0:
                self.save("tokens_header", header, read_only=True)
                first_token = token

        endpoint = AUTH_URI + '/tokens'

        # TEST GET ALL TOKENS (expected at least num_tokens)
        r = client.get(endpoint, headers=self.get("tokens_header"))
        content = self.get_content(r)
        assert r.status_code == hcodes.HTTP_OK_BASIC
        assert len(content) >= num_tokens

        # save a token to be used for further tests
        for c in content:
            if c["token"] == first_token:
                continue
            self.save("token_id", c["id"])

        # TEST GET SINGLE TOKEN
        endpoint_single = "{}/{}".format(endpoint, self.get("token_id"))
        r = client.get(endpoint_single, headers=self.get("tokens_header"))
        assert r.status_code == hcodes.HTTP_OK_BASIC

        # TEST GET INVALID SINGLE TOKEN
        r = client.get(endpoint + "/0", headers=self.get("tokens_header"))
        assert r.status_code == hcodes.HTTP_BAD_NOTFOUND

    def test_07_DELETE_tokens(self, client):

        endpoint = AUTH_URI + '/tokens'
        endpoint_single = "{}/{}".format(endpoint, self.get("token_id"))

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

    def test_08_admin_users(self, client):

        headers, _ = self.do_login(client, None, None)
        endpoint = "admin/users"
        url = API_URI + "/" + endpoint
        get_r, _, _, _ = self._test_endpoint(
            client,
            endpoint,
            headers,
            hcodes.HTTP_OK_BASIC,
            hcodes.HTTP_BAD_REQUEST,
            hcodes.HTTP_BAD_METHOD_NOT_ALLOWED,
            hcodes.HTTP_BAD_METHOD_NOT_ALLOWED,
        )

        self.checkResponse(get_r, [], [])

        r = client.get(url, headers=headers)
        assert r.status_code == hcodes.HTTP_OK_BASIC

        schema = self.getDynamicInputSchema(client, endpoint, headers)
        data = self.buildData(schema)
        r = client.post(url, data=data, headers=headers)
        assert r.status_code == hcodes.HTTP_OK_BASIC
        uuid = self.get_content(r)

        # Check duplicates
        r = client.post(url, data=data, headers=headers)
        assert r.status_code == hcodes.HTTP_BAD_CONFLICT

        # Create another user to test duplicates on put
        data2 = self.buildData(schema)
        r = client.post(url, data=data2, headers=headers)
        assert r.status_code == hcodes.HTTP_OK_BASIC
        uuid2 = self.get_content(r)

        r = client.get(url + "/" + uuid, headers=headers)
        assert r.status_code == hcodes.HTTP_OK_BASIC

        r = client.put(url + "/" + uuid, data={'name': 'Changed'}, headers=headers)
        assert r.status_code == hcodes.HTTP_OK_NORESPONSE

        # update user2 with email of user1
        new_data = {'email': data.get('email')}
        r = client.put(url + "/" + uuid2, data=new_data, headers=headers)
        assert r.status_code == hcodes.HTTP_BAD_CONFLICT

        r = client.delete(url + "/" + uuid, headers=headers)
        assert r.status_code == hcodes.HTTP_OK_NORESPONSE

        r = client.get(url + "/" + uuid, headers=headers)
        assert r.status_code == hcodes.HTTP_BAD_NOTFOUND

        # login with a newly created user
        headers2, _ = self.do_login(
            client,
            data2.get("username"),
            data2.get("password")
        )

        # normal users cannot access to this endpoint
        r = client.get(url, headers=headers)
        assert r.status_code == hcodes.HTTP_BAD_UNAUTHORIZED

        r = client.get(url + "/" + uuid, headers=headers)
        assert r.status_code == hcodes.HTTP_BAD_UNAUTHORIZED

        r = client.post(url, data=data, headers=headers)
        assert r.status_code == hcodes.HTTP_BAD_UNAUTHORIZED

        r = client.put(url + "/" + uuid, data={'name': 'Changed'}, headers=headers2)
        assert r.status_code == hcodes.HTTP_BAD_UNAUTHORIZED

        r = client.delete(url + "/" + uuid, headers=headers2)
        assert r.status_code == hcodes.HTTP_BAD_UNAUTHORIZED

        # let's delete the second user
        r = client.delete(url + "/" + uuid2, headers=headers)
        assert r.status_code == hcodes.HTTP_OK_NORESPONSE

        endpoint = AUTH_URI + '/logout'

        r = client.get(endpoint, headers=headers)
        assert r.status_code == hcodes.HTTP_OK_NORESPONSE

        r = client.get(endpoint, headers=headers2)
        assert r.status_code == hcodes.HTTP_OK_NORESPONSE