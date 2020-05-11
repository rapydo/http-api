# -*- coding: utf-8 -*-

"""
Tests for http api base (mostly authentication)
"""


from restapi.tests import BaseTests, API_URI, AUTH_URI, BaseAuthentication
from restapi.services.detect import detector
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
        assert r.status_code == 200
        output = self.get_content(r)
        assert output == alive_message

        # Check failure
        log.info("*** VERIFY if invalid endpoint gives Not Found")
        r = client.get(API_URI)
        assert r.status_code == 404

        # Check HTML response to status if agent/request is text/html
        headers = {"Accept": 'text/html'}
        r = client.get(endpoint, headers=headers)
        assert r.status_code == 200
        output = r.data.decode('utf-8')
        assert output != alive_message
        assert alive_message in output
        assert "<html" in output
        assert "<body>" in output

        # Check /auth/status with no token or invalid token
        r = client.get(AUTH_URI + '/status')
        assert r.status_code == 401

        r = client.get(AUTH_URI + '/status', headers={'Authorization': 'Bearer ABC'})
        assert r.status_code == 401

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
            client, USER, PWD.upper(), status_code=401
        )

        log.info("*** VERIFY valid credentials")
        headers, _ = self.do_login(client, None, None)
        self.save("auth_header", headers)

        # Verify credentials
        r = client.get(AUTH_URI + '/status', headers=headers)
        assert r.status_code == 200
        c = self.get_content(r)
        assert isinstance(c, bool) and c

        # Check failure
        log.info("*** VERIFY invalid credentials")

        self.do_login(
            client,
            'ABC-Random-User-XYZ',
            'ABC-Random-Pass-XYZ',
            status_code=401,
        )

        # this check verifies a BUG with neo4j causing crash of auth module
        # when using a non-email-username to authenticate
        log.info("*** VERIFY with a non-email-username")

        self.do_login(
            client,
            'notanemail',
            '[A-Za-z0-9]+',
            status_code=401,
        )

    def test_04_GET_profile(self, client):
        """ Check if you can use your token for protected endpoints """

        endpoint = AUTH_URI + '/profile'

        # Check success
        log.info("*** VERIFY valid token")
        r = client.get(endpoint, headers=self.get("auth_header"))
        assert r.status_code == 200

        # Check failure
        log.info("*** VERIFY invalid token")
        r = client.get(endpoint)
        assert r.status_code == 401

    def test_05_GET_logout(self, client):
        """ Check that you can logout with a valid token """

        endpoint = AUTH_URI + '/logout'

        # Check success
        log.info("*** VERIFY valid token")
        r = client.get(endpoint, headers=self.get("auth_header"))
        assert r.status_code == 204

        # Check failure
        log.info("*** VERIFY invalid token")
        r = client.get(endpoint)
        assert r.status_code == 401

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
        assert r.status_code == 200
        assert len(content) >= num_tokens

        # save a token to be used for further tests
        for c in content:
            if c["token"] == first_token:
                continue
            self.save("token_id", c["id"])

        # SINGLE TOKEN IS NOT ALLOWED
        endpoint_single = "{}/{}".format(endpoint, self.get("token_id"))
        r = client.get(endpoint_single, headers=self.get("tokens_header"))
        assert r.status_code == 405

        # TEST GET ALL TOKENS (expected at least num_tokens)
        r = client.get(API_URI + "/admin/tokens", headers=self.get("tokens_header"))
        content = self.get_content(r)
        assert r.status_code == 200
        assert len(content) >= num_tokens

        # DELETE INVALID TOKEN
        r = client.delete(
            API_URI + "/admin/tokens/xyz",
            headers=self.get("tokens_header")
        )
        assert r.status_code == 404

    def test_07_DELETE_tokens(self, client):

        endpoint = AUTH_URI + '/tokens'
        endpoint_single = "{}/{}".format(endpoint, self.get("token_id"))

        # TEST DELETE OF A SINGLE TOKEN
        r = client.delete(endpoint_single, headers=self.get("tokens_header"))
        assert r.status_code == 204

        # TEST AN ALREADY DELETED TOKEN
        r = client.delete(endpoint_single, headers=self.get("tokens_header"))
        assert r.status_code == 401

        # TEST INVALID DELETE OF A SINGLE TOKEN
        r = client.delete(endpoint + "/0", headers=self.get("tokens_header"))
        assert r.status_code == 401

        # TEST TOKEN IS STILL VALID
        r = client.get(endpoint, headers=self.get("tokens_header"))
        assert r.status_code == 200

    def test_08_admin_users(self, client):

        if detector.get_bool_from_os("ADMINER_DISABLED"):
            log.warning("SKipp admin/users tests")
            return

        headers, _ = self.do_login(client, None, None)
        endpoint = "admin/users"
        url = API_URI + "/" + endpoint
        self._test_endpoint(
            client,
            endpoint,
            headers,
            200,
            400,
            405,
            405,
        )

        r = client.get(url, headers=headers)
        assert r.status_code == 200

        schema = self.getDynamicInputSchema(client, endpoint, headers)
        data = self.buildData(schema)
        r = client.post(url, data=data, headers=headers)
        assert r.status_code == 200
        uuid = self.get_content(r)

        r = client.get(url + "/" + uuid, headers=headers)
        assert r.status_code == 200
        users_list = self.get_content(r)
        assert len(users_list) > 0
        # email is saved lowercase
        assert users_list[0].get("email") == data.get('email').lower()

        # Check duplicates
        r = client.post(url, data=data, headers=headers)
        assert r.status_code == 409

        # Create another user to test duplicates
        data2 = self.buildData(schema)
        r = client.post(url, data=data2, headers=headers)
        assert r.status_code == 200
        uuid2 = self.get_content(r)

        r = client.put(url + "/" + uuid, data={'name': 'Changed'}, headers=headers)
        assert r.status_code == 204

        # email cannot be modiied
        new_data = {'email': data.get('email')}
        r = client.put(url + "/" + uuid2, data=new_data, headers=headers)
        assert r.status_code == 204

        r = client.get(url + "/" + uuid2, headers=headers)
        assert r.status_code == 200
        users_list = self.get_content(r)
        assert len(users_list) > 0
        # email is not modified -> still equal to data2, not data1
        assert users_list[0].get("email") != data.get('email').lower()
        assert users_list[0].get("email") == data2.get('email').lower()

        r = client.delete(url + "/" + uuid, headers=headers)
        assert r.status_code == 204

        r = client.get(url + "/" + uuid, headers=headers)
        assert r.status_code == 404

        # login with a newly created user
        headers2, _ = self.do_login(
            client,
            data2.get("email"),
            data2.get("password")
        )

        # normal users cannot access to this endpoint
        r = client.get(url, headers=headers2)
        assert r.status_code == 401

        r = client.get(url + "/" + uuid, headers=headers2)
        assert r.status_code == 401

        r = client.post(url, data=data, headers=headers2)
        assert r.status_code == 401

        r = client.put(url + "/" + uuid, data={'name': 'Changed'}, headers=headers2)
        assert r.status_code == 401

        r = client.delete(url + "/" + uuid, headers=headers2)
        assert r.status_code == 401

        # Users are not authorized to /admin/tokens
        r = client.get(API_URI + "/admin/tokens", headers=headers2)
        assert r.status_code == 401
        r = client.delete(API_URI + "/admin/tokens/xyz", headers=headers2)
        assert r.status_code == 401

        # let's delete the second user
        r = client.delete(url + "/" + uuid2, headers=headers)
        assert r.status_code == 204

        endpoint = AUTH_URI + '/logout'

        r = client.get(endpoint, headers=headers)
        assert r.status_code == 204

    # tests to be completed
    def test_09_profile(self, client):

        if not detector.get_bool_from_os("MAIN_LOGIN_ENABLE"):
            log.warning("Profile is disabled, skipping tests")
            return True

        headers, _ = self.do_login(client, None, None)

        # update profile, no auth
        r = client.put(AUTH_URI + "/" + 'profile')
        assert r.status_code == 401

        # update profile, no data
        r = client.put(AUTH_URI + "/" + 'profile', data={}, headers=headers)
        assert r.status_code == 204

        newname = 'newname'

        r = client.get(AUTH_URI + "/" + 'profile', headers=headers)
        assert r.status_code == 200
        c = self.get_content(r)
        assert c.get('name') != newname

        # update profile
        data = {'name': 'newname'}
        r = client.put(AUTH_URI + "/" + 'profile', data=data, headers=headers)
        assert r.status_code == 204

        r = client.get(AUTH_URI + "/" + 'profile', headers=headers)
        assert r.status_code == 200
        c = self.get_content(r)
        assert c.get('name') == newname

    def test_10_registration(self, client):

        if not detector.get_bool_from_os("ALLOW_REGISTRATION"):
            log.warning("User registration is disabled, skipping tests")
            return True

        # registration, empty input
        r = client.post(AUTH_URI + '/profile')
        assert r.status_code == 400
        assert self.get_content(r) == 'Empty input'

        # registration, missing information
        data = {'x': 'y'}
        r = client.post(AUTH_URI + '/profile', data=data)
        assert r.status_code == 400
        assert self.get_content(r) == 'Missing input: password'
        data = {}
        data['password'] = self.randomString()
        r = client.post(AUTH_URI + '/profile', data=data)
        assert r.status_code == 400
        assert self.get_content(r) == 'Missing input: email'
        data['email'] = BaseAuthentication.default_user
        r = client.post(AUTH_URI + '/profile', data=data)
        assert r.status_code == 400
        assert self.get_content(r) == 'Missing input: name'
        data['name'] = 'Mr'
        r = client.post(AUTH_URI + '/profile', data=data)
        assert r.status_code == 400
        assert self.get_content(r) == 'Missing input: surname'

        data['surname'] = 'Brown'
        r = client.post(AUTH_URI + '/profile', data=data)
        assert r.status_code == 400
        m = "This user already exists: {}".format(BaseAuthentication.default_user)
        assert self.get_content(r) == m

        data['email'] = 'mock@nomail.org'
        r = client.post(AUTH_URI + '/profile', data=data)
        # now the user is created, but inactive...
        # how to get the token sent via email???
        assert r.status_code == 200

        # profile activation
        r = client.put(AUTH_URI + '/profile/activate/thisisatoken')
        # this token is not valid
        assert r.status_code == 400

        # Ask a new activation link
        r = client.post(AUTH_URI + '/profile/activate')
        assert r.status_code == 400
        assert self.get_content(r) == 'Empty input'

        # activation, missing information
        r = client.post(AUTH_URI + '/profile/activate', data={'x': 'y'})
        assert r.status_code == 400
        assert self.get_content(r) == 'Missing required input: username'

        # activation, wrong username
        r = client.post(AUTH_URI + '/profile/activate', data={'username': 'y'})
        # return is 200, ma no mail will be sent... how to test this??
        assert r.status_code == 200

    def test_11_password_reset(self, client):

        if not detector.get_bool_from_os("ALLOW_PASSWORD_RESET"):
            log.warning("Password reset is disabled, skipping tests")
            return True

        # Request password reset, missing information
        r = client.post(AUTH_URI + '/reset')
        assert r.status_code == 403
        assert self.get_content(r) == 'Invalid reset email'

        # Request password reset, missing information
        r = client.post(AUTH_URI + '/reset', data={'x': 'y'})
        assert r.status_code == 403
        assert self.get_content(r) == 'Invalid reset email'

        # Request password reset, wrong email
        r = client.post(AUTH_URI + '/reset', data={'reset_email': 'y'})
        assert r.status_code == 403
        assert self.get_content(r) == 'Sorry, y is not recognized as a valid username'

        # Do password reset
        r = client.put(AUTH_URI + '/reset/thisisatoken')
        # this token is not valid
        assert r.status_code == 400
