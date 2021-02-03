import json
import os
import re
import secrets
import string
import urllib.parse
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

import jwt
import pyotp
import pytest
import pytz
from faker import Faker
from faker.providers import BaseProvider
from flask.wrappers import Response

from restapi.config import (
    API_URL,
    AUTH_URL,
    DEFAULT_HOST,
    DEFAULT_PORT,
    SECRET_KEY_FILE,
)
from restapi.connectors import Connector
from restapi.env import Env
from restapi.services.authentication import BaseAuthentication, Payload
from restapi.utilities.logs import log

SERVER_URI = f"http://{DEFAULT_HOST}:{DEFAULT_PORT}"
API_URI = f"{SERVER_URI}{API_URL}"
AUTH_URI = f"{SERVER_URI}{AUTH_URL}"

# Should be:
# from flask.testing import FlaskClient
# but it raises Missing type parameters for generic type "FlaskClient"
# I cannot understand how to fix this... so let's fallback to Any...
FlaskClient = Any


# Create a random password to be used to build data for tests
class PasswordProvider(BaseProvider):
    def password(
        self,
        length: int = 8,
        strong: bool = False,  # this enables all low, up, digits and symbols
        low: bool = True,
        up: bool = False,
        digits: bool = False,
        symbols: bool = False,
    ) -> str:

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


def get_faker() -> Faker:

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
    QRsecrets: Dict[str, str] = {}
    TOTP = False

    @classmethod
    def save(cls, variable: str, value: Any) -> None:
        """
        Save a variable in the class, to be re-used in further tests
        """

        setattr(cls, variable, value)

    @classmethod
    def get(cls, variable: str) -> Any:
        """
        Retrieve a previously stored variable using the .save method
        """
        if hasattr(cls, variable):
            return getattr(cls, variable)

        raise AttributeError(f"Class variable {variable} not found")

    @staticmethod
    def getDynamicInputSchema(
        client: FlaskClient, endpoint: str, headers: Optional[Dict[str, str]]
    ) -> Any:
        """
        Retrieve a dynamic data schema associated with a endpoint
        """

        r = client.post(
            f"{API_URI}/{endpoint}", data={"get_schema": 1}, headers=headers
        )
        assert r.status_code == 200

        return json.loads(r.data.decode("utf-8"))

    @staticmethod
    def get_content(http_out: Response) -> Any:

        try:
            response = json.loads(http_out.get_data().decode())
        except Exception as e:  # pragma: no cover
            log.error("Failed to load response:\n{}", e)
            raise ValueError(f"Malformed response: {http_out}")

        return response

    @staticmethod
    def generate_totp(email: Optional[str]) -> Optional[str]:
        assert email is not None
        secret = BaseTests.QRsecrets.get(email.lower())
        if secret:
            return pyotp.TOTP(secret).now()

        auth = Connector.get_authentication_instance()

        user = auth.get_user(username=email)

        if user is None:
            log.error("Can't find a user for {}", email)
            return None

        secret = auth.get_totp_secret(user)

        return pyotp.TOTP(secret).now()

    @staticmethod
    def do_login(
        client: FlaskClient,
        USER: Optional[str],
        PWD: Optional[str],
        status_code: int = 200,
        error: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
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

        assert USER is not None
        assert PWD is not None

        if data is None:
            data = {}

        data["username"] = USER
        data["password"] = PWD

        r = client.post(f"{AUTH_URI}/login", data=data)
        content = json.loads(r.data.decode("utf-8"))

        if r.status_code == 403:

            # This 403 is expected, return an invalid value or you can enter a loop!
            if status_code == 403:
                return None, None

            if isinstance(content, dict) and content.get("actions"):
                actions = content.get("actions", [])

                for action in actions:
                    if action == "TOTP":
                        BaseTests.TOTP = True
                        continue
                    if action == "FIRST LOGIN":
                        continue
                    if action == "PASSWORD EXPIRED":
                        continue

                data = {}
                # Will read and store qr_code + init totp_code required for next action
                if "TOTP" in actions:
                    if content.get("qr_code"):
                        # validate that the QR code is a valid PNG image
                        pass

                    if qr_url := content.get("qr_url", ""):
                        assert isinstance(qr_url, str)
                        assert qr_url.startswith("otpauth://totp/")
                        assert "?secret=" in qr_url
                        secret = qr_url.split("?secret=")[1]
                        assert secret is not None
                        assert len(secret) == 16

                        BaseTests.QRsecrets[USER.lower()] = secret

                if "FIRST LOGIN" in actions or "PASSWORD EXPIRED" in actions:
                    newpwd = fake.password(strong=True)
                    data["new_password"] = newpwd
                    data["password_confirm"] = fake.password(strong=True)
                    if BaseTests.TOTP:
                        data["totp_code"] = BaseTests.generate_totp(USER)

                    BaseTests.do_login(
                        client,
                        USER,
                        PWD,
                        data=data,
                        status_code=409,
                    )

                    # Test failure of password change if TOTP is wrong or not provided
                    if BaseTests.TOTP:
                        data["new_password"] = newpwd
                        data["password_confirm"] = newpwd
                        data.pop("totp_code", None)

                        BaseTests.do_login(
                            client,
                            USER,
                            PWD,
                            data=data,
                            status_code=403,
                        )

                        data["new_password"] = newpwd
                        data["password_confirm"] = newpwd
                        # random int with 6 digits
                        data["totp_code"] = fake.pyint(
                            min_value=100000, max_value=999999
                        )
                        BaseTests.do_login(
                            client,
                            USER,
                            PWD,
                            data=data,
                            status_code=401,
                        )

                    # Change the password to silence FIRST_LOGIN and PASSWORD_EXPIRED
                    data["new_password"] = newpwd
                    data["password_confirm"] = newpwd
                    if BaseTests.TOTP:
                        data["totp_code"] = BaseTests.generate_totp(USER)
                    BaseTests.do_login(
                        client,
                        USER,
                        PWD,
                        data=data,
                    )
                    # Change again to restore the default password
                    # and keep all other tests fully working
                    data["new_password"] = PWD
                    data["password_confirm"] = PWD
                    if BaseTests.TOTP:
                        data["totp_code"] = BaseTests.generate_totp(USER)
                    return BaseTests.do_login(
                        client,
                        USER,
                        newpwd,
                        data=data,
                    )

                # in this case FIRST LOGIN has not been executed
                # => login by sending the TOTP code
                if "TOTP" in actions:
                    # random int with 6 digits
                    data["totp_code"] = fake.pyint(min_value=100000, max_value=999999)
                    BaseTests.do_login(
                        client,
                        USER,
                        PWD,
                        data=data,
                        status_code=401,
                    )

                    data["totp_code"] = BaseTests.generate_totp(USER)
                    return BaseTests.do_login(
                        client,
                        USER,
                        PWD,
                        data=data,
                    )

        # FOR DEBUGGING WHEN ADVANCED AUTH OPTIONS ARE ON
        # if r.status_code != 200:
        #     c = json.loads(r.data.decode("utf-8"))
        #     log.error(c)

        assert r.status_code == status_code

        if error is not None:
            assert content == error

        # when 200 OK content is the token
        assert content is not None

        return {"Authorization": f"Bearer {content}"}, content

    @classmethod
    def create_user(
        cls, client: FlaskClient, data: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, Dict[str, Any]]:

        assert not Env.get_bool("ADMINER_DISABLED")

        admin_headers, _ = cls.do_login(client, None, None)
        assert admin_headers is not None
        schema = cls.getDynamicInputSchema(client, "admin/users", admin_headers)
        user_data = cls.buildData(schema)
        if Connector.check_availability("smtp"):
            user_data["email_notification"] = False
        user_data["is_active"] = True
        user_data["expiration"] = None
        if data:
            user_data.update(data)
        r = client.post(f"{API_URI}/admin/users", data=user_data, headers=admin_headers)
        assert r.status_code == 200
        uuid = cls.get_content(r)

        return uuid, user_data

    @classmethod
    def delete_user(cls, client: FlaskClient, uuid: str) -> None:

        assert not Env.get_bool("ADMINER_DISABLED")

        admin_headers, _ = cls.do_login(client, None, None)
        assert admin_headers is not None
        r = client.delete(f"{API_URI}/admin/users/{uuid}", headers=admin_headers)
        assert r.status_code == 204

    @staticmethod
    def buildData(schema: Any) -> Dict[str, Any]:
        """
        Input: a Marshmallow schema
        Output: a dictionary of random data
        """
        data = {}
        for d in schema:

            key = d.get("key")
            field_type = d.get("type")

            if "options" in d:
                if len(d["options"]) > 0:
                    keys = list(d["options"].keys())
                    if d.get("multiple", False):
                        # requests is unable to send lists, if not json-dumped
                        data[key] = json.dumps([fake.random_element(keys)])
                    else:
                        data[key] = fake.random_element(keys)
                # else:  # pragma: no cover
                #     pytest.fail(f"BuildData for {key}: invalid options (empty?)")
            elif field_type == "number" or field_type == "int":
                min_value = d.get("min", 0)
                max_value = d.get("max", 9999)
                data[key] = fake.pyint(min_value=min_value, max_value=max_value)
            elif field_type == "date":
                # d = fake.date(pattern="%Y-%m-%d")
                # data[key] = f"{d}T00:00:00.000Z"
                data[key] = f"{fake.iso8601()}.000Z"
            elif field_type == "email":
                data[key] = fake.ascii_email()
            elif field_type == "boolean":
                data[key] = fake.pybool()
            elif field_type == "password":
                data[key] = fake.password(strong=True)
            elif field_type == "string":
                data[key] = fake.pystr(min_chars=16, max_chars=32)
            else:  # pragma: no cover
                pytest.fail(f"BuildData for {key}: unknow type {field_type}")

        return data

    @staticmethod
    def read_mock_email() -> Any:
        fpath = "/logs/mock.mail.lastsent.json"
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

    @staticmethod
    def get_token_from_body(body: str) -> Optional[str]:
        token = None

        # if a token is not found the email is considered to be plain text
        if "</a>" not in body:
            token = body[1 + body.rfind("/") :]
        # if a token is found the email is considered to be html
        else:
            urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
            if urls:
                # token is the last part of the url, extract as a path
                token = os.path.basename(urls[0])

        if token:
            token = urllib.parse.unquote(token)

        return token

    @staticmethod
    def get_crafted_token(
        token_type: str,
        user_id: Optional[str] = None,
        expired: bool = False,
        immature: bool = False,
        wrong_secret: bool = False,
        wrong_algorithm: bool = False,
    ) -> str:

        if wrong_secret:
            secret = fake.password()
        else:
            secret = open(SECRET_KEY_FILE, "rb").read()

        if wrong_algorithm:
            algorithm = "HS256"
        else:
            algorithm = BaseAuthentication.JWT_ALGO

        if user_id is None:
            user_id = str(uuid.uuid4())

        payload: Payload = {"user_id": user_id, "jti": str(uuid.uuid4())}
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
