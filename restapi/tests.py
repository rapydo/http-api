import base64
import json
import os
import re
import urllib.parse
import uuid
from collections import namedtuple
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union

import jwt
import pyotp
import pytest
import pytz
from faker import Faker
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
from restapi.services.authentication import BaseAuthentication, Payload, Role
from restapi.utilities.faker import get_faker
from restapi.utilities.logs import log

SERVER_URI = f"http://{DEFAULT_HOST}:{DEFAULT_PORT}"
API_URI = f"{SERVER_URI}{API_URL}"
AUTH_URI = f"{SERVER_URI}{AUTH_URL}"

# Should be:
# from flask.testing import FlaskClient
# but it raises Missing type parameters for generic type "FlaskClient"
# I cannot understand how to fix this... so let's fallback to Any...
FlaskClient = Any

Event = namedtuple(
    "Event", ["date", "ip", "user", "event", "target_type", "target_id", "payload"]
)


class BaseTests:

    faker: Faker = get_faker()
    # This will store credentials to be used to test unused credentials ban
    # Tuple = (email, password, uuid)
    unused_credentials: Optional[Tuple[str, str, str]] = None

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

        raise AttributeError(f"Class variable {variable} not found")  # pragma: no cover

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
    def generate_totp(email: Optional[str]) -> str:
        assert email is not None
        auth = Connector.get_authentication_instance()

        user = auth.get_user(username=email.lower())

        secret = auth.get_totp_secret(user)

        return pyotp.TOTP(secret).now()

    @classmethod
    def do_login(
        cls,
        client: FlaskClient,
        USER: Optional[str],
        PWD: Optional[str],
        status_code: int = 200,
        data: Optional[Dict[str, Any]] = None,
        test_failures: bool = False,
    ) -> Tuple[Optional[Dict[str, str]], str]:
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
                return None, content

            if isinstance(content, dict) and content.get("actions"):
                actions = content.get("actions", [])

                for action in actions:
                    if action == "TOTP":
                        continue
                    if action == "FIRST LOGIN":
                        continue
                    if action == "PASSWORD EXPIRED":
                        continue

                data = {}

                if "FIRST LOGIN" in actions or "PASSWORD EXPIRED" in actions:
                    newpwd = cls.faker.password(strong=True)
                    if test_failures:
                        data["new_password"] = newpwd
                        data["password_confirm"] = cls.faker.password(strong=True)
                        if Env.get_bool("AUTH_SECOND_FACTOR_AUTHENTICATION"):
                            data["totp_code"] = BaseTests.generate_totp(USER)

                        BaseTests.do_login(
                            client,
                            USER,
                            PWD,
                            data=data,
                            status_code=409,
                        )

                        # Test failure of password change if TOTP is wrong or missing
                        if Env.get_bool("AUTH_SECOND_FACTOR_AUTHENTICATION"):
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
                            data["totp_code"] = cls.faker.pyint(
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
                    if Env.get_bool("AUTH_SECOND_FACTOR_AUTHENTICATION"):
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
                    if Env.get_bool("AUTH_SECOND_FACTOR_AUTHENTICATION"):
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
                    # Only directly tested => no coverage
                    if test_failures:  # pragma: no cover
                        # random int with 6 digits
                        data["totp_code"] = cls.faker.pyint(
                            min_value=100000, max_value=999999
                        )
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

        # when 200 OK content is the token
        assert content is not None

        return {"Authorization": f"Bearer {content}"}, content

    @classmethod
    def create_user(
        cls,
        client: FlaskClient,
        data: Optional[Dict[str, Any]] = None,
        roles: Optional[List[Union[str, Role]]] = None,
    ) -> Tuple[str, Dict[str, Any]]:

        assert Env.get_bool("MAIN_LOGIN_ENABLE")

        admin_headers, _ = cls.do_login(client, None, None)
        assert admin_headers is not None
        schema = cls.getDynamicInputSchema(client, "admin/users", admin_headers)
        user_data = cls.buildData(schema)
        if Connector.check_availability("smtp"):
            user_data["email_notification"] = False
        user_data["is_active"] = True
        user_data["expiration"] = None

        if roles:
            for idx, role in enumerate(roles):
                if isinstance(role, Role):
                    roles[idx] = role.value

            user_data["roles"] = json.dumps(roles)

        if data:
            user_data.update(data)
        r = client.post(f"{API_URI}/admin/users", data=user_data, headers=admin_headers)
        assert r.status_code == 200
        uuid = cls.get_content(r)

        return uuid, user_data

    @classmethod
    def delete_user(cls, client: FlaskClient, uuid: str) -> None:

        assert Env.get_bool("MAIN_LOGIN_ENABLE")

        admin_headers, _ = cls.do_login(client, None, None)
        assert admin_headers is not None
        r = client.delete(f"{API_URI}/admin/users/{uuid}", headers=admin_headers)
        assert r.status_code == 204

    @classmethod
    def create_group(
        cls, client: FlaskClient, data: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, Dict[str, Any]]:

        assert Env.get_bool("MAIN_LOGIN_ENABLE")

        admin_headers, _ = cls.do_login(client, None, None)
        assert admin_headers is not None
        schema = cls.getDynamicInputSchema(client, "admin/groups", admin_headers)
        group_data = cls.buildData(schema)
        if data:
            group_data.update(data)
        r = client.post(
            f"{API_URI}/admin/groups", data=group_data, headers=admin_headers
        )
        assert r.status_code == 200
        uuid = cls.get_content(r)

        return uuid, group_data

    @classmethod
    def buildData(cls, schema: Any) -> Dict[str, Any]:
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
                        data[key] = json.dumps([cls.faker.random_element(keys)])
                    else:
                        data[key] = cls.faker.random_element(keys)
                # else:  # pragma: no cover
                #     pytest.fail(f"BuildData for {key}: invalid options (empty?)")
            elif field_type == "number" or field_type == "int":
                min_value = d.get("min", 0)
                max_value = d.get("max", 9999)
                data[key] = cls.faker.pyint(min_value=min_value, max_value=max_value)
            elif field_type == "date":
                # d = cls.faker.date(pattern="%Y-%m-%d")
                # data[key] = f"{d}T00:00:00.000Z"
                data[key] = f"{cls.faker.iso8601()}.000Z"
            elif field_type == "email":
                data[key] = cls.faker.ascii_email()
            elif field_type == "boolean":
                data[key] = cls.faker.pybool()
            elif field_type == "password":
                data[key] = cls.faker.password(strong=True)
            elif field_type == "string":
                data[key] = cls.faker.pystr(min_chars=16, max_chars=32)
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

            log.warning("Inspecting Email: {}", data)

        if "msg" in data:
            tokens = data["msg"].split("\n\n")
            data["headers"] = tokens[0]
            data["body"] = "".join(tokens[1:])

        # Longer email are base64 encoded
        # It happens with activation email from MeteoHub
        if "Content-Transfer-Encoding: base64" in data["body"]:  # pragma: no cover
            encodings = data["body"].split("Content-Transfer-Encoding: base64")
            base64_body = re.sub(r"--===============.*$", "", encodings[1])

            # b64decode gives as output bytes, decode("utf-8") needed to get string
            data["body"] = base64.b64decode(base64_body.replace("\n", "")).decode(
                "utf-8"
            )

        os.unlink(fpath)
        return data

    @staticmethod
    def get_token_from_body(body: str) -> Optional[str]:
        token = None

        # Debug code:
        log.warning("Inspecting email body: {}", body)

        # if a token is not found the email is considered to be plain text
        if "</a>" not in body:
            token = body[1 + body.rfind("/") :]
        # if a token is found the email is considered to be html
        else:
            urls = re.findall(
                r'href=["|\'](https?://[^\s<>"]+|www\.[^\s<>"]+)["|\']', body
            )

            log.warning("Found urls: {}", urls)
            if urls:
                # token is the last part of the url, extract as a path
                token = os.path.basename(urls[0])

        if token:
            token = urllib.parse.unquote(token)

        return token

    @classmethod
    def get_crafted_token(
        cls,
        token_type: str,
        user_id: Optional[str] = None,
        expired: bool = False,
        immature: bool = False,
        wrong_secret: bool = False,
        wrong_algorithm: bool = False,
    ) -> str:

        if wrong_secret:
            secret = cls.faker.password()
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

    @staticmethod
    def event_matches_filters(event: Event, filters: Dict[str, str]) -> bool:

        for filt, value in filters.items():  # pragma: no cover
            if filt == "date" and event.date != value:
                return False
            if filt == "ip" and event.ip != value:
                return False
            if filt == "user" and event.user != value:
                return False
            if filt == "event" and event.event != value:
                return False
            if filt == "target_type" and event.target_type != value:
                return False
            if filt == "target_id" and event.target_id != value:
                return False
            # filter by payload ... ?
        return True

    @classmethod
    def get_last_events(
        cls, num: int = 1, filters: Optional[Dict[str, str]] = None
    ) -> List[Event]:

        fpath = "/logs/security-events.log"
        if not os.path.exists(fpath):  # pragma: no cover
            return []

        with open(fpath) as file:
            # Not efficient read the whole file to get the last lines, to be improved!
            lines = file.readlines()
            lines.reverse()

            events: List[Event] = []
            # read last num lines
            for line in lines:

                # Found enough events, let's stop
                if len(events) == num:
                    break

                tokens = line.strip().split(" ")

                payload = json.loads(" ".join(tokens[7:])) if len(tokens) >= 8 else {}

                event = Event(
                    # datetime
                    f"{tokens[0]} {tokens[1]}",
                    # IP Address
                    tokens[2],
                    # User email or -
                    tokens[3],
                    # Event name
                    tokens[4],
                    # Target type or empty
                    tokens[5] if len(tokens) >= 6 else "",
                    # Target ID or empty
                    tokens[6] if len(tokens) >= 7 else "",
                    # Payload dictionary
                    payload,
                )

                if filters and not cls.event_matches_filters(event, filters):
                    continue

                events.append(event)

        events.reverse()
        return events
