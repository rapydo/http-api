import json
import os
import secrets
import string
import uuid
from datetime import datetime, timedelta

import jwt
import pyotp
import pytest
import pytz
from faker import Faker
from faker.providers import BaseProvider

from restapi.confs import API_URL, AUTH_URL, DEFAULT_HOST, DEFAULT_PORT
from restapi.services.authentication import BaseAuthentication
from restapi.utilities.logs import log

SERVER_URI = f"http://{DEFAULT_HOST}:{DEFAULT_PORT}"
API_URI = f"{SERVER_URI}{API_URL}"
AUTH_URI = f"{SERVER_URI}{AUTH_URL}"


# Create a random password to be used to build data for tests
class PasswordProvider(BaseProvider):
    def password(
        self,
        length=8,
        strong=False,  # this enables all low, up, digits and symbols
        low=True,
        up=False,
        digits=False,
        symbols=False,
    ):

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

        rand = secrets.SystemRandom()

        randstr = "".join(rand.choices(charset, k=length))
        if low and not any(s in randstr for s in string.ascii_lowercase):
            log.warning(
                f"{randstr} is not strong enough: missing lower case. Sampling again..."
            )
            return self.password(
                length, strong=strong, low=low, up=up, digits=digits, symbols=symbols
            )
        if up and not any(s in randstr for s in string.ascii_uppercase):
            log.warning(
                f"{randstr} is not strong enough: missing upper case. Sampling again..."
            )
            return self.password(
                length, strong=strong, low=low, up=up, digits=digits, symbols=symbols
            )
        if digits and not any(s in randstr for s in string.digits):
            log.warning(
                f"{randstr} is not strong enough: missing digits. Sampling again..."
            )
            return self.password(
                length, strong=strong, low=low, up=up, digits=digits, symbols=symbols
            )
        if symbols and not any(s in randstr for s in string.punctuation):
            log.warning(
                f"{randstr} is not strong enough: missing symbols. Sampling again..."
            )
            return self.password(
                length, strong=strong, low=low, up=up, digits=digits, symbols=symbols
            )

        return randstr


def get_faker():

    locales = {
        "ar_EG": "Arabic",
        "bg_BG": "Bulgarian",
        "bs_BA": "Bosnian",
        "cs_CZ": "Czech",
        "de_DE": "German",
        "dk_DK": "Danish",
        "el_GR": "Greek",
        "en_US": "English",
        "es_ES": "Spanish",
        "et_EE": "Estonian",
        "fa_IR": "Persian",
        "fi_FI": "Finnish",
        "fr_FR": "French",
        "hi_IN": "Hindi",
        "hr_HR": "Croatian",
        "hu_HU": "Hungarian",
        # 'hy_AM': 'Armenian',
        "it_IT": "Italian",
        "ja_JP": "Japanese",
        "ka_GE": "Georgian",
        "ko_KR": "Korean",
        "lt_LT": "Lithuanian",
        "lv_LV": "Latvian",
        "ne_NP": "Nepali",
        "nl_NL": "Dutch",
        "no_NO": "Norwegian",
        "pl_PL": "Polish",
        "pt_PT": "Portuguese",
        "ro_RO": "Romanian",
        "ru_RU": "Russian",
        "sl_SI": "Slovene",
        "sv_SE": "Swedish",
        "tr_TR": "Turkish",
        "uk_UA": "Ukrainian",
        "zh_CN": "Chinese",
    }

    loc = secrets.choice(list(locales.keys()))
    log.warning(f"Today I'm {locales.get(loc)}")
    fake = Faker(loc)

    fake.add_provider(PasswordProvider)

    return fake


# How to inject the fixture in the class constructor or definition
# and make available to all methods?
fake = get_faker()


class BaseTests:

    # will be used by do_login in case of TOTP
    # This will save correspondances between user email and provided QR Code
    QRsecrets = {}

    def save(self, variable, value, read_only=False):
        """
            Save a variable in the class, to be re-used in further tests
            In read_only mode the variable cannot be rewritten
        """
        if hasattr(self.__class__, variable):
            data = getattr(self.__class__, variable)
            if "read_only" in data and data["read_only"]:
                pytest.fail(f"Cannot overwrite a read_only variable [{variable}]")

        data = {"value": value, "read_only": read_only}
        setattr(self.__class__, variable, data)

    def get(self, variable):
        """
            Retrieve a previously stored variable using the .save method
        """
        if hasattr(self.__class__, variable):
            data = getattr(self.__class__, variable)
            if "value" in data:
                return data["value"]

        raise AttributeError(f"Class variable {variable} not found")

    @staticmethod
    def get_specs(client):
        """
            Retrieve Swagger definition by calling API/specs endpoint
        """
        r = client.get(f"{API_URI}/specs")
        assert r.status_code == 200
        content = json.loads(r.data.decode("utf-8"))
        return content

    @staticmethod
    def getDynamicInputSchema(client, endpoint, headers, html=False):
        """
            Retrieve a dynamic data schema associated with a endpoint
        """

        data = {"get_schema": 1}

        h = headers.copy()
        if html:
            h["Accept"] = "text/html"

        r = client.post(f"{API_URI}/{endpoint}", data=data, headers=h)
        assert r.status_code == 200

        content = r.data.decode("utf-8")
        if html:
            return content

        return json.loads(content)

    @staticmethod
    def get_content(http_out):

        try:
            response = json.loads(http_out.get_data().decode())
        except Exception as e:  # pragma: no cover
            log.error("Failed to load response:\n{}", e)
            raise ValueError(f"Malformed response: {http_out}")

        return response

    @staticmethod
    def generate_totp(secret):
        if secret is None:
            # someway to reset the TOTP secret?
            pytest.fail(
                "Unavailable TOTP secret, probably you missed the FIRST LOGIN action?"
            )
        return pyotp.TOTP(secret).now()

    @staticmethod
    def do_login(client, USER, PWD, status_code=200, error=None, data=None):
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

        data["username"] = USER
        data["password"] = PWD

        r = client.post(f"{AUTH_URI}/login", data=data)
        content = json.loads(r.data.decode("utf-8"))

        if r.status_code == 403:
            if isinstance(content, dict) and content.get("actions"):
                actions = content.get("actions", [])

                for action in actions:
                    if action == "TOTP":
                        continue
                    if action == "FIRST LOGIN":
                        continue
                    if action == "PASSWORD EXPIRED":
                        continue
                    pytest.fail(f"Unknown post log action requested: {action}")

                data = {}
                # Will read and store qr_code + init totp_code required for next action
                if "TOTP" in actions:
                    if content.get("qr_code"):
                        # validate that the QR code is a valid PNG image
                        pass

                    if content.get("qr_url"):
                        assert content.get("qr_url").startswith("otpauth://totp/")
                        assert "?secret=" in content.get("qr_url")
                        secret = content.get("qr_url").split("?secret=")[1]
                        assert secret is not None
                        # uhm?
                        assert len(secret) == 16

                        BaseTests.QRsecrets[USER.lower()] = secret

                    data["totp_code"] = BaseTests.generate_totp(
                        BaseTests.QRsecrets.get(USER.lower())
                    )

                if "FIRST LOGIN" in actions or "PASSWORD EXPIRED" in actions:
                    newpwd = fake.password(strong=True)
                    data["new_password"] = newpwd
                    data["password_confirm"] = fake.password(strong=True)
                    BaseTests.do_login(
                        client, USER, PWD, data=data, status_code=409,
                    )
                    # Change the password to silence FIRST_LOGIN and PASSWORD_EXPIRED
                    data["new_password"] = newpwd
                    data["password_confirm"] = newpwd
                    BaseTests.do_login(
                        client, USER, PWD, data=data,
                    )
                    # Change again to restore the default password
                    # and keep all other tests fully working
                    data["new_password"] = PWD
                    data["password_confirm"] = PWD
                    return BaseTests.do_login(client, USER, newpwd, data=data,)

                # in this case FIRST LOGIN has not been executed
                # => login by sending the TOTP code
                if "TOTP" in actions:
                    data["totp_code"] = fake.pyint()
                    BaseTests.do_login(
                        client, USER, PWD, data=data, status_code=401,
                    )

                    data["totp_code"] = BaseTests.generate_totp(
                        BaseTests.QRsecrets.get(USER.lower())
                    )
                    return BaseTests.do_login(client, USER, PWD, data=data,)

        if r.status_code != 200:
            # VERY IMPORTANT FOR DEBUGGING WHEN ADVANCED AUTH OPTIONS ARE ON
            c = json.loads(r.data.decode("utf-8"))
            log.error(c)

        assert r.status_code == status_code

        if error is not None:
            assert content == error

        # when 200 OK content is the token
        assert content is not None

        return {"Authorization": f"Bearer {content}"}, content

    def randomString(self, length=16, prefix=""):  # pragma: no cover
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

            if "enum" in d:
                if len(d["enum"]) > 0:
                    data[key] = fake.random_element(list(d["enum"].keys()))
                else:
                    pytest.fail(f"BuildData for {key}: invalid enum (empty?)")
            elif field_type == "number" or field_type == "int":
                data[key] = fake.pyint()
            elif field_type == "date":
                data[key] = fake.date(pattern="%Y-%m-%d")
            elif field_type == "email":
                data[key] = fake.ascii_email()
            elif field_type == "boolean":
                data[key] = fake.pybool()
            elif field_type == "password":
                data[key] = fake.password(strong=True)
            elif field_type == "string":
                data[key] = fake.pystr(min_chars=16, max_chars=32)
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

        if headers is not None:

            if self.method_exists(get_status):
                r = client.get(f"{API_URI}/{endpoint}")
                assert r.status_code == 401

            if self.method_exists(post_status):
                r = client.post(f"{API_URI}/{endpoint}", data=post_data)
                assert r.status_code == 401

            if self.method_exists(put_status):
                r = client.put(f"{API_URI}/{endpoint}")
                assert r.status_code == 401

            if self.method_exists(del_status):
                r = client.delete(f"{API_URI}/{endpoint}")
                assert r.status_code == 401

        get_r = post_r = put_r = delete_r = None

        if get_status is not None:
            get_r = client.get(f"{API_URI}/{endpoint}", headers=headers)
            assert get_r.status_code == get_status

        if post_status is not None:
            post_r = client.post(
                f"{API_URI}/{endpoint}", headers=headers, data=post_data
            )
            assert post_r.status_code == post_status

        if put_status is not None:
            put_r = client.put(f"{API_URI}/{endpoint}", headers=headers)
            assert put_r.status_code == put_status

        if del_status is not None:
            delete_r = client.delete(f"{API_URI}/{endpoint}", headers=headers)
            assert delete_r.status_code == del_status

        return get_r, post_r, put_r, delete_r

    @staticmethod
    def read_mock_email():
        fpath = "/code/mock.mail.lastsent.json"
        if not os.path.exists(fpath):
            return None

        with open(fpath) as file:
            data = json.load(file)
        if "msg" in data:
            tokens = data["msg"].split("\n\n")
            data["headers"] = tokens[0]
            data["body"] = "".join(tokens[1:])

        os.unlink(fpath)
        return data

    def get_crafted_token(
        self,
        token_type,
        user_id=None,
        expired=False,
        immature=False,
        wrong_secret=False,
        wrong_algorithm=False,
    ):

        if wrong_secret:
            secret = fake.password()
        else:
            f = os.getenv("JWT_APP_SECRETS") + "/secret.key"
            secret = open(f, "rb").read()

        if wrong_algorithm:
            algorithm = "HS256"
        else:
            algorithm = BaseAuthentication.JWT_ALGO

        if user_id is None:
            user_id = str(uuid.uuid4())

        payload = {"user_id": user_id, "jti": str(uuid.uuid4())}
        payload["t"] = token_type
        now = datetime.now(pytz.utc)
        payload["iat"] = now
        if immature:
            payload["nbf"] = now + timedelta(seconds=999)
        else:
            payload["nbf"] = now - timedelta(seconds=999)
        if expired:
            payload["exp"] = now - timedelta(seconds=999)
        else:
            payload["exp"] = now + timedelta(seconds=999)

        token = jwt.encode(payload, secret, algorithm=algorithm).decode("ascii")

        return token
