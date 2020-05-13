# -*- coding: utf-8 -*-
import os
import pytest
import json
import string
import random
from glom import glom

from restapi.confs import DEFAULT_HOST, DEFAULT_PORT, API_URL, AUTH_URL
from restapi.services.authentication import BaseAuthentication

from restapi.utilities.logs import log

SERVER_URI = 'http://{}:{}'.format(DEFAULT_HOST, DEFAULT_PORT)
API_URI = '{}{}'.format(SERVER_URI, API_URL)
AUTH_URI = '{}{}'.format(SERVER_URI, AUTH_URL)


class BaseTests:
    def save(self, variable, value, read_only=False):
        """
            Save a variable in the class, to be re-used in further tests
            In read_only mode the variable cannot be rewritten
        """
        if hasattr(self.__class__, variable):
            data = getattr(self.__class__, variable)
            if "read_only" in data and data["read_only"]:
                pytest.fail(
                    "Cannot overwrite a read_only variable [{}]".format(variable))

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

        raise AttributeError("Class variable {} not found".format(variable))

    @staticmethod
    def get_specs(client):
        """
            Retrieve Swagger definition by calling API/specs endpoint
        """
        r = client.get(API_URI + '/specs')
        assert r.status_code == 200
        content = json.loads(r.data.decode('utf-8'))
        return content

    @staticmethod
    def getInputSchema(client, endpoint, headers):
        """
            Retrieve a swagger-like data schema associated with a endpoint
        """
        r = client.get(API_URI + '/schemas/' + endpoint, headers=headers)
        assert r.status_code == 200
        content = json.loads(r.data.decode('utf-8'))
        if 'Response' in content:
            return content['Response']['data']
        return content

    @staticmethod
    def getDynamicInputSchema(client, endpoint, headers):
        """
            Retrieve a dynamic data schema associated with a endpoint
        """

        data = {"get_schema": 1}
        r = client.post("{}/{}".format(API_URI, endpoint), data=data, headers=headers)
        assert r.status_code == 200
        content = json.loads(r.data.decode('utf-8'))
        if 'Response' in content:
            return content['Response']['data']
        return content

    @staticmethod
    def get_content(http_out):

        try:
            response = json.loads(http_out.get_data().decode())
        except Exception as e:
            log.error("Failed to load response:\n{}", e)
            raise ValueError(
                "Malformed response: {}".format(http_out)
            )

        # Should be {Response: DATA, Meta: RESPONSE_METADATA}
        # To be removed when WRAP_RESPONSE will be removed
        if isinstance(response, dict) and len(response) == 2:
            content = glom(response, "Response.data", default=None)

            if content is None:
                content = glom(response, "Response.errors", default=None)

            if content is not None:
                return content

        return response

    def do_login(self, client, USER, PWD,
                 status_code=200, error=None,
                 user_field='username', pwd_field='password',
                 data=None):
        """
            Make login and return both token and authorization header
        """

        if USER is None or PWD is None:
            BaseAuthentication.myinit()
            if USER is None:
                USER = BaseAuthentication.default_user
            if PWD is None:
                PWD = BaseAuthentication.default_password

        if data is None:
            data = {}

        data[user_field] = USER
        data[pwd_field] = PWD

        r = client.post(AUTH_URI + '/login', data=json.dumps(data))
        content = json.loads(r.data.decode('utf-8'))

        if r.status_code == 403:
            if isinstance(content, dict) and content.get('actions'):
                action = content.get('actions')[0]

                if action == 'FIRST LOGIN' or action == 'PASSWORD EXPIRED':
                    newpwd = "Aa1!{}".format(self.randomString())
                    headers, _ = self.do_login(
                        client, USER, PWD,
                        data={
                            'new_password': newpwd,
                            'password_confirm': format(self.randomString()),
                        },
                        status_code=409,
                    )
                    # Change the password to silence FIRST_LOGIN and PASSWORD_EXPIRED
                    self.do_login(
                        client, USER, PWD,
                        data={
                            'new_password': newpwd,
                            'password_confirm': newpwd,
                        }
                    )
                    # Change again to restore the default password
                    # and keep all other tests fully working
                    return self.do_login(
                        client, USER, newpwd,
                        data={
                            'new_password': PWD,
                            'password_confirm': PWD,
                        }
                    )
                else:
                    pytest.fail(
                        "Unknown post log action requested: {}".format(action)
                    )

        if r.status_code != 200:
            # VERY IMPORTANT FOR DEBUGGING WHEN ADVANCED AUTH OPTIONS ARE ON
            c = json.loads(r.data.decode('utf-8'))
            if 'Response' in c:
                log.error(c['Response']['errors'])
            else:
                log.error(c)

        assert r.status_code == status_code

        if error is not None:
            if 'Response' in content:
                errors = content['Response']['errors']
                if errors is not None:
                    assert errors[0] == error
            else:
                assert content == error

        token = ''
        if content is not None:
            token = glom(content, "Response.data.token", default=None)
            if token is None:
                token = content
        return {'Authorization': 'Bearer {}'.format(token)}, token

    # Only used by nig
    # def create_user(self, username, **kwargs):

    #     users_def = self.get("def.users")
    #     user_def = self.get("def.user")
    #     admin_headers = self.get("admin_headers")
    #     endpoint = 'admin/users'

    #     # This prefix ensure a strong password

    #     if "password" in kwargs:
    #         password = kwargs.pop("password")
    #     else:
    #         password = self.randomString(prefix="Aa1+")

    #     user = self.get_user_uuid(username)

    #     if user is not None:
    #         self._test_delete(user_def, 'admin/users/' + user,
    #                           admin_headers, 204)

    #     data = {}
    #     data['email'] = username
    #     data['password'] = password
    #     data['name'] = username
    #     data['surname'] = username

    #     for v in kwargs:
    #         data[v] = kwargs[v]

    #     # data['group'] = group
    #     # if irods_user is not None:
    #     #     data['irods_user'] = irods_user

    #     # if irods_cert is not None:
    #     #     data['irods_cert'] = irods_cert

    #     user = self._test_create(
    #         users_def, endpoint, admin_headers, data, 200)

    #     env = os.environ
    #     CHANGE_FIRST_PASSWORD = env.get("AUTH_FORCE_FIRST_PASSWORD_CHANGE")

    #     if CHANGE_FIRST_PASSWORD:
    #         error = "Please change your temporary password"
    #         self.do_login(username, password,
    #                       status_code=403, error=error)

    #         new_password = self.randomString(prefix="Aa1+")
    #         data = {
    #             "new_password": new_password,
    #             "password_confirm": new_password
    #         }

    #         self.do_login(
    #             username, password, status_code=200, **data)
    #         # password change also changes the uuid
    #         user = self.get_user_uuid(username)
    #         password = new_password

    #     return user, password

    # only used by nig
    # def get_profile(self, headers, client):
    #     r = client.get(AUTH_URI + '/profile', headers=headers)
    #     content = json.loads(r.data.decode('utf-8'))
    #     if 'Response' in content:
    #         return content['Response']['data']
    #     return content

    @staticmethod
    def get_celery(app):

        from restapi.connectors.celery import CeleryExt
        from restapi.services.detect import detector

        celery = detector.connectors_instances.get('celery')
        celery.celery_app.app = app
        CeleryExt.celery_app = celery.celery_app
        return CeleryExt

    @staticmethod
    def randomString(length=16, prefix="TEST-"):
        """
            Create a random string to be used to build data for tests
        """
        rand = random.SystemRandom()
        charset = string.ascii_uppercase + string.digits

        random_string = prefix
        for _ in range(length):
            random_string += rand.choice(charset)

        return random_string

    @staticmethod
    def checkResponse(response, fields, relationships):
        """
        Verify that the response contains the given fields and relationships
        """

        for f in fields:
            if f not in response[0]:
                pytest.fail("Missing property: {}".format(f))

        for r in relationships:
            if "_{}".format(r) not in response[0]:
                pytest.fail("Missing relationship: {}".format(r))

    def buildData(self, schema):
        """
            Input: a Swagger-like schema
            Output: a dictionary of random data
        """
        data = {}
        for d in schema:

            key = d.get("name")
            if key is None:
                key = d.get("key")
            field_type = d.get("type")
            field_format = d.get("format", "")
            default = d.get("default", None)
            custom = d.get("custom", {})
            autocomplete = custom.get("autocomplete", False)
            test_with = custom.get("test_with", None)

            if autocomplete and test_with is None:
                continue

            value = None
            if test_with is not None:
                value = test_with
            elif 'enum' in d:
                if default is not None:
                    value = default
                elif len(d["enum"]) > 0:
                    # get first key
                    for value in d["enum"][0]:
                        break
                else:
                    value = "NOT_FOUND"
            elif field_type == "number" or field_type == "int":
                value = random.SystemRandom().randrange(0, 1000, 1)
            elif field_format == "date":
                value = "1969-07-20"  # 20:17:40 UTC
            elif field_type == "email" or field_format == "email":
                value = self.randomString()
                value += "@nomail.com"
            elif field_type == "multi_section":
                continue
            elif field_type == "boolean":
                value = True
            else:
                value = self.randomString()

            data[key] = value

        return data

    # only used by nig
    # def getPartialData(self, schema, data):
    #     """
    #         Following directives contained in the schema and
    #         taking as input a pre-built data dictionary, this method
    #         remove one of the required fields from data
    #     """
    #     partialData = data.copy()
    #     for d in schema:
    #         if not d['required']:
    #             continue

    #         # key = d["key"]
    #         key = d["name"]

    #         del partialData[key]
    #         return partialData
    #     return None

    @staticmethod
    def method_exists(status):
        if status is None:
            return False
        if status == 404:
            return False
        if status == 405:
            return False

        return True

    def _test_endpoint(
        self,
        client,
        endpoint,
        headers=None,
        get_status=None,
        post_status=None,
        put_status=None,
        del_status=None,
        post_data=None,
    ):

        endpoint = "{}/{}".format(API_URI, endpoint)

        if headers is not None:

            if self.method_exists(get_status):
                r = client.get(endpoint)
                assert r.status_code == 401

            if self.method_exists(post_status):
                r = client.post(endpoint, data=post_data)
                assert r.status_code == 401

            if self.method_exists(put_status):
                r = client.put(endpoint)
                assert r.status_code == 401

            if self.method_exists(del_status):
                r = client.delete(endpoint)
                assert r.status_code == 401

        get_r = post_r = put_r = delete_r = None

        if get_status is not None:
            get_r = client.get(endpoint, headers=headers)
            assert get_r.status_code == get_status

        if post_status is not None:
            post_r = client.post(endpoint, headers=headers, data=post_data)
            assert post_r.status_code == post_status

        if put_status is not None:
            put_r = client.put(endpoint, headers=headers)
            assert put_r.status_code == put_status

        if del_status is not None:
            delete_r = client.delete(endpoint, headers=headers)
            assert delete_r.status_code == del_status

        return get_r, post_r, put_r, delete_r

    @staticmethod
    def read_mock_email():
        fpath = "/tmp/mock.mail.lastsent.json"
        if not os.path.exists(fpath):
            return None

        with open(fpath, 'r') as file:
            data = json.load(file)
        if 'msg' in data:
            data['msg'] = data['msg'].split("\n")
        else:
            data['msg'] = []
        data['parsed_message'] = {}
        for d in data['msg']:
            tokens = d.split(": ")
            if len(tokens) == 2:
                data['parsed_message'][tokens[0]] = tokens[1]
            else:
                data['body'] = d

        os.unlink(fpath)
        return data
