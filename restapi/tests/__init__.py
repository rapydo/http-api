# -*- coding: utf-8 -*-

"""
@mattia: why is this file here, and why I see thing copied from the old
tests/__init__.py?
"""

import pytest
import json
import string
import random
# import os

from restapi.confs import DEFAULT_HOST, DEFAULT_PORT, API_URL, AUTH_URL
from restapi.rest.response import get_content_from_response
from restapi.services.authentication import BaseAuthentication
from utilities import htmlcodes as hcodes

from utilities.logs import get_logger

log = get_logger(__name__)

SERVER_URI = 'http://%s:%s' % (DEFAULT_HOST, DEFAULT_PORT)
API_URI = '%s%s' % (SERVER_URI, API_URL)
AUTH_URI = '%s%s' % (SERVER_URI, AUTH_URL)


class BaseTests(object):

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

    def get_specs(self, client):
        """
            Retrieve Swagger definition by calling API/specs endpoint
        """
        r = client.get(API_URI + '/specs')
        assert r.status_code == hcodes.HTTP_OK_BASIC
        content = json.loads(r.data.decode('utf-8'))
        return content

    def get_definition(self, specs, endpoint):
        """
            Given a swagger specs this method extracts a swagger definition
            for a specific endpoint. The endpoint is expected to have variables
            defined following swagger rules, e.g /path/{variable}
        """
        mapping = "%s/%s" % (API_URL, endpoint)

        assert mapping in specs["paths"]
        return specs["paths"][mapping]

    def getInputSchema(self, client, endpoint, headers):
        """
            Retrieve a swagger-like data schema associated with a endpoint
        """
        r = client.get(API_URI + '/schemas/' + endpoint, headers=headers)
        assert r.status_code == hcodes.HTTP_OK_BASIC
        content = json.loads(r.data.decode('utf-8'))
        return content['Response']['data']

    def getDynamicInputSchema(self, client, endpoint, headers):
        """
            Retrieve a dynamic data schema associated with a endpoint
        """

        data = {"get_schema": 1}
        r = client.post(
            "%s/%s" % (API_URI, endpoint),
            data=data,
            headers=headers)
        assert r.status_code == hcodes.HTTP_OK_BASIC
        content = json.loads(r.data.decode('utf-8'))
        return content['Response']['data']

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

    def do_login(self, client, USER, PWD,
                 status_code=hcodes.HTTP_OK_BASIC,
                 error=None, **kwargs):
        """
            Make login and return both token and authorization header
        """

        if USER is None or PWD is None:
            BaseAuthentication.myinit()
            if USER is None:
                USER = BaseAuthentication.default_user
            if PWD is None:
                PWD = BaseAuthentication.default_password

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

    def do_logout(self, client, headers):
        r = client.get(AUTH_URI + '/logout', headers=headers)
        if r.status_code == hcodes.HTTP_OK_NORESPONSE:
            log.info("Test TOKEN removed")
        else:
            log.error("Failed to logout with:\n%s", headers)

    def delete_tokens(self, client, headers):
        # r = client.delete(AUTH_URI + '/tokens', headers=headers)
        pass

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
    #                           admin_headers, hcodes.HTTP_OK_NORESPONSE)

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
    #         users_def, endpoint, admin_headers, data, hcodes.HTTP_OK_BASIC)

    #     env = os.environ
    #     CHANGE_FIRST_PASSWORD = env.get("AUTH_FORCE_FIRST_PASSWORD_CHANGE")

    #     if CHANGE_FIRST_PASSWORD:
    #         error = "Please change your temporary password"
    #         self.do_login(username, password,
    #                       status_code=hcodes.HTTP_BAD_FORBIDDEN, error=error)

    #         new_password = self.randomString(prefix="Aa1+")
    #         data = {
    #             "new_password": new_password,
    #             "password_confirm": new_password
    #         }

    #         self.do_login(
    #             username, password, status_code=hcodes.HTTP_OK_BASIC, **data)
    #         # password change also changes the uuid
    #         user = self.get_user_uuid(username)
    #         password = new_password

    #     return user, password

    def get_profile(self, headers, client):
        r = client.get(AUTH_URI + '/profile', headers=headers)
        content = json.loads(r.data.decode('utf-8'))
        return content['Response']['data']

    def get_celery(self, app):

        from restapi.flask_ext.flask_celery import CeleryExt
        from restapi.services.detect import detector
        celery = detector.extensions_instances.get('celery')
        celery.celery_app.app = app
        CeleryExt.celery_app = celery.celery_app
        return CeleryExt

    def randomString(self, len=16, prefix="TEST-"):
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

    def checkResponse(self, response, fields, relationships):
        """
        Verify that the response contains the given fields and relationships
        """

        for f in fields:
            if f not in response[0]["attributes"]:
                pytest.fail("Missing property: %s" % f)

        for r in relationships:
            if r not in response[0]["relationships"]:
                pytest.fail("Missing relationship: %s" % r)

    def buildData(self, schema):
        """
            Input: a Swagger-like schema
            Output: a dictionary of random data
        """
        data = {}
        for d in schema:

            key = d["name"]
            field_type = d["type"]
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
                value = random.randrange(0, 1000, 1)
            elif field_format == "date":
                value = "1969-07-20"  # 20:17:40 UTC
            elif field_format == "email":
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

    def getPartialData(self, schema, data):
        """
            Following directives contained in the schema and
            taking as input a pre-built data dictionary, this method
            remove one of the required fields from data
        """
        partialData = data.copy()
        for d in schema:
            if not d['required']:
                continue

            # key = d["key"]
            key = d["name"]

            del partialData[key]
            return partialData
        return None

    @staticmethod
    def method_exists(status):
        if status is None:
            return False
        if status == hcodes.HTTP_BAD_NOTFOUND:
            return False
        if status == hcodes.HTTP_BAD_METHOD_NOT_ALLOWED:
            return False

        return True

    def _test_endpoint(self, client, endpoint, headers=None,
                       get_status=None, post_status=None,
                       put_status=None, del_status=None,
                       post_data=None):

        endpoint = "%s/%s" % (API_URI, endpoint)

        if headers is not None:

            if self.method_exists(get_status):
                r = client.get(endpoint)
                assert r.status_code == hcodes.HTTP_BAD_UNAUTHORIZED

            if self.method_exists(post_status):
                r = client.post(endpoint, data=post_data)
                assert r.status_code == hcodes.HTTP_BAD_UNAUTHORIZED

            if self.method_exists(put_status):
                r = client.put(endpoint)
                assert r.status_code == hcodes.HTTP_BAD_UNAUTHORIZED

            if self.method_exists(del_status):
                r = client.delete(endpoint)
                assert r.status_code == hcodes.HTTP_BAD_UNAUTHORIZED

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
