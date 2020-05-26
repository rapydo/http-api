# -*- coding: utf-8 -*-
import os
import pytest
import json
import jwt
import uuid
import pytz
import string
import random
from datetime import datetime, timedelta
from glom import glom
from faker import Faker
from faker.providers import BaseProvider

from restapi.confs import DEFAULT_HOST, DEFAULT_PORT, API_URL, AUTH_URL
from restapi.services.authentication import BaseAuthentication

from restapi.utilities.logs import log

SERVER_URI = 'http://{}:{}'.format(DEFAULT_HOST, DEFAULT_PORT)
API_URI = '{}{}'.format(SERVER_URI, API_URL)
AUTH_URI = '{}{}'.format(SERVER_URI, AUTH_URL)


# Create a random password to be used to build data for tests
class PasswordProvider(BaseProvider):
    def password(self, length=8,
                 strong=False,  # this enables all low, up, digits and symbols
                 low=True, up=False, digits=False, symbols=False):

        if strong:
            if length < 16:
                length = 16
            low = True
            up = True
            digits = True
            symbols = True

        charset = ""
        if low:
            charset += string.ascii_lowercase
        if up:
            charset += string.ascii_uppercase
        if digits:
            charset += string.digits
        if symbols:
            charset += string.punctuation

        rand = random.SystemRandom()

        randstr = ''.join(rand.choices(charset, k=length))
        if low and not any(s in randstr for s in string.ascii_lowercase):
            log.warning(
                "String {} not strong enough, missing lower case characters".format(
                    randstr
                )
            )
            return self.password(
                length, strong=strong,
                low=low, up=up, digits=digits, symbols=symbols
            )
        if up and not any(s in randstr for s in string.ascii_uppercase):
            log.warning(
                "String {} not strong enough, missing upper case characters".format(
                    randstr
                )
            )
            return self.password(
                length, strong=strong,
                low=low, up=up, digits=digits, symbols=symbols
            )
        if digits and not any(s in randstr for s in string.digits):
            log.warning(
                "String {} not strong enough, missing digits".format(
                    randstr
                )
            )
            return self.password(
                length, strong=strong,
                low=low, up=up, digits=digits, symbols=symbols
            )
        if symbols and not any(s in randstr for s in string.punctuation):
            log.warning(
                "String {} not strong enough, missing symbols".format(
                    randstr
                )
            )
            return self.password(
                length, strong=strong,
                low=low, up=up, digits=digits, symbols=symbols
            )

        return randstr


def get_faker():
    fake = Faker()

    fake.add_provider(PasswordProvider)


fake = get_faker()

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
    def getDynamicInputSchema(client, endpoint, headers):
        """
            Retrieve a dynamic data schema associated with a endpoint
        """

        data = {"get_schema": 1}
        r = client.post("{}/{}".format(API_URI, endpoint), data=data, headers=headers)
        assert r.status_code == 200
        content = json.loads(r.data.decode('utf-8'))
        return content

    @staticmethod
    def get_content(http_out):

        try:
            response = json.loads(http_out.get_data().decode())
        except Exception as e:  # pragma: no cover
            log.error("Failed to load response:\n{}", e)
            raise ValueError(
                "Malformed response: {}".format(http_out)
            )

        return response

    def do_login(self, client, USER, PWD,
                 status_code=200, error=None, data=None):
        """
            Make login and return both token and authorization header
        """

        if USER is None or PWD is None:
            BaseAuthentication.load_default_user()
            BaseAuthentication.load_roles()
            if USER is None:
                USER = BaseAuthentication.default_user
            if PWD is None:
                PWD = BaseAuthentication.default_password

        if data is None:
            data = {}

        data['username'] = USER
        data['password'] = PWD

        r = client.post(AUTH_URI + '/login', data=data)
        content = json.loads(r.data.decode('utf-8'))

        if r.status_code == 403:
            if isinstance(content, dict) and content.get('actions'):
                action = content.get('actions')[0]

                if action == 'FIRST LOGIN' or action == 'PASSWORD EXPIRED':
                    newpwd = fake.password(strong=True)
                    self.do_login(
                        client, USER, PWD,
                        data={
                            'new_password': newpwd,
                            'password_confirm': fake.password(strong=True),
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
            log.error(c)

        assert r.status_code == status_code

        if error is not None:
            assert content == error

        # when 200 OK content is the token
        assert content is not None

        return {'Authorization': 'Bearer {}'.format(content)}, content

    @staticmethod
    def get_celery(app):

        from restapi.connectors.celery import CeleryExt
        from restapi.services.detect import detector

        celery = glom(detector.services, "celery.connector")
        celery.celery_app.app = app
        CeleryExt.celery_app = celery.celery_app
        return CeleryExt

    def randomString(self, length=16, prefix=""):
        # Deprecated since 0.7.4
        log.warning("Deprecated, use fake.password instead")
        return prefix + fake.password(
            length, low=False, up=True, digits=True, symbols=False
        )

    def buildData(self, schema):
        """
            Input: a webargs schema
            Output: a dictionary of random data
        """
        data = {}
        for d in schema:

            key = d.get("key")
            field_type = d.get("type")

            if 'enum' in d:
                if len(d["enum"]) > 0:
                    data[key] = fake.random_element(list(d["enum"].keys()))
                else:
                    pytest.fail(f"BuildData for {key}: invalid enum (empty?)")
            elif field_type == "number" or field_type == "int":
                data[key] = fake.random_int()
            elif field_type == "date":
                data[key] = fake.date(pattern='%Y-%m-%d')
            elif field_type == "email":
                data[key] = fake.ascii_email()
            elif field_type == "boolean":
                data[key] = fake.random_elements((True, False))
            elif field_type == "password":
                data[key] = fake.password(strong=True)
            elif field_type == "string":
                # a totally random string is something like a strong password
                data[key] = fake.password(strong=True)
            else:
                pytest.fail(f"BuildData for {key}: unknow type {field_type}")

        return data

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
        fpath = "/code/mock.mail.lastsent.json"
        if not os.path.exists(fpath):
            return None

        with open(fpath, 'r') as file:
            data = json.load(file)
        if 'msg' in data:
            tokens = data['msg'].split("\n\n")
            data['headers'] = tokens[0]
            data['body'] = ''.join(tokens[1:])

        os.unlink(fpath)
        return data

    def get_crafted_token(self, token_type, user_id=None,
                          expired=False, immature=False,
                          wrong_secret=False, wrong_algorithm=False):

        if wrong_secret:
            secret = fake.password()
        else:
            f = os.getenv('JWT_APP_SECRETS') + "/secret.key"
            secret = open(f, 'rb').read()

        if wrong_algorithm:
            algorithm = "HS256"
        else:
            algorithm = BaseAuthentication.JWT_ALGO

        if user_id is None:
            user_id = str(uuid.uuid4())

        payload = {
            'user_id': user_id,
            'jti': str(uuid.uuid4())
        }
        payload["t"] = token_type
        now = datetime.now(pytz.utc)
        payload['iat'] = now
        if immature:
            payload['nbf'] = now + timedelta(seconds=999)
        else:
            payload['nbf'] = now - timedelta(seconds=999)
        if expired:
            payload['exp'] = now - timedelta(seconds=999)
        else:
            payload['exp'] = now + timedelta(seconds=999)

        token = jwt.encode(
            payload,
            secret,
            algorithm=algorithm
        ).decode('ascii')

        return token
