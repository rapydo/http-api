import base64
import os
import re
import urllib.parse
import uuid
from collections import namedtuple
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple, TypedDict, Union, cast

import jwt
import orjson
import pyotp
import pytest
import pytz
from faker import Faker
from flask import Flask
from flask.testing import FlaskClient
from werkzeug.test import TestResponse as Response

from restapi.config import (
    API_URL,
    AUTH_URL,
    CODE_DIR,
    DEFAULT_HOST,
    DEFAULT_PORT,
    JWT_SECRET_FILE,
    get_frontend_url,
)
from restapi.connectors import Connector, celery
from restapi.env import Env
from restapi.services.authentication import BaseAuthentication, Role
from restapi.utilities.faker import get_faker
from restapi.utilities.logs import LOGS_FOLDER, Events, log


class MockedEmail(TypedDict):
    # from: str
    cc: List[str]
    msg: str
    # body and headers are added by read_mock_email function
    body: str
    headers: str


SERVER_URI = f"http://{DEFAULT_HOST}:{DEFAULT_PORT}"
API_URI = f"{SERVER_URI}{API_URL}"
AUTH_URI = f"{SERVER_URI}{AUTH_URL}"

Event = namedtuple(
    "Event",
    ["date", "ip", "user", "event", "target_type", "target_id", "url", "payload"],
)


@contextmanager
def execute_from_code_dir() -> Generator[None, None, None]:
    """Sets the cwd within the context"""

    origin = Path().absolute()
    try:
        os.chdir(CODE_DIR)
        yield
    finally:
        os.chdir(origin)


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
        client: FlaskClient,
        endpoint: str,
        headers: Optional[Dict[str, str]],
        method: str = "post",
    ) -> List[Dict[str, Any]]:
        """
        Retrieve a dynamic data schema associated with a endpoint
        """

        method = method.lower()

        if method == "post":
            r = client.post(
                f"{API_URI}/{endpoint}", data={"get_schema": 1}, headers=headers
            )
        else:
            r = client.put(
                f"{API_URI}/{endpoint}", data={"get_schema": 1}, headers=headers
            )

        assert r.status_code == 200

        schema = orjson.loads(r.data.decode("utf-8"))
        assert isinstance(schema, list)
        for f in schema:
            assert isinstance(f, dict)
        return schema

    @staticmethod
    def get_content(
        http_out: Response,
    ) -> Union[str, float, int, bool, List[Any], Dict[str, Any]]:

        try:
            response = orjson.loads(http_out.get_data().decode())
            if isinstance(
                response,
                (
                    str,
                    bool,
                    float,
                    int,
                    list,
                    dict,
                ),
            ):
                return response

            raise ValueError(  # pragma: no cover
                f"Unknown response type: {type(response)}"
            )
        except Exception as e:  # pragma: no cover
            log.error("Failed to load response:\n{}", e)
            raise ValueError(f"Malformed response: {http_out}")

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

        if not Connector.check_availability("authentication"):  # pragma: no cover
            pytest.fail("Authentication is not enabled")

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
        content = orjson.loads(r.data.decode("utf-8"))

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

                    events = cls.get_last_events(1)
                    assert events[0].event == Events.password_expired.value
                    # assert events[0].user == USER

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
        #     c = orjson.loads(r.data.decode("utf-8"))
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

            user_data["roles"] = orjson.dumps(roles).decode("UTF8")

        if data:
            user_data.update(data)
        r = client.post(f"{API_URI}/admin/users", data=user_data, headers=admin_headers)
        assert r.status_code == 200
        uuid = cls.get_content(r)
        assert isinstance(uuid, str)

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
        assert isinstance(uuid, str)

        return uuid, group_data

    # Simple wrappers to ensure names and surnames longer than 3 characters
    # Note: short names/surnamed are not verified for password strenght checks
    @classmethod
    def get_first_name(cls, faker: Faker, recursion: int = 0) -> str:
        # Please Faker, add some types hints and let me remove this str()!
        name = str(faker.first_name())
        if len(name) > 3:
            return name

        # Probably this Faker locale only has very short names.
        # It can happens with Chinese?
        # Let's return a repetition of the name it self
        if recursion >= 10:  # pragma: no cover
            return name * 4
        return cls.get_first_name(faker, recursion=recursion + 1)  # pragma: no cover

    @classmethod
    def get_last_name(cls, faker: Faker, recursion: int = 0) -> str:
        # Please Faker, add some types hints and let me remove this str()!
        surname = str(faker.last_name())
        if len(surname) > 3:
            # Please Faker, add some types hints!
            return surname
        # Probably this Faker locale only has very short names.
        # It can happens with Chinese?
        # Let's return a repetition of the name it self
        if recursion >= 10:  # pragma: no cover
            return surname * 4
        return cls.get_last_name(faker, recursion=recursion + 1)  # pragma: no cover

    @classmethod
    def get_random_email(
        cls, faker: Faker, name: str, surname: str, recursion: int = 0
    ) -> str:
        # Please Faker, add some types hints and let me remove this str()!
        email = str(faker.ascii_email())

        # This email contains the name, re-sampling again
        if name.lower() in email.lower():  # pragma: no cover
            return cls.get_random_email(faker, name, surname, recursion=recursion + 1)

        # This email contains the surname, re-sampling again
        if surname.lower() in email.lower():  # pragma: no cover
            return cls.get_random_email(faker, name, surname, recursion=recursion + 1)

        email_tokens = email.split("@")
        email_username = email_tokens[0]
        if len(email_username) > 3:
            # Please Faker, add some types hints!
            return email

        # Probably this Faker locale only has very short emails.
        # It can happens with Chinese?
        # Let's return a repetition of the name it self
        if recursion >= 10:  # pragma: no cover
            return f"{email_username * 4}@{email_tokens[1]}"

        return cls.get_random_email(  # pragma: no cover
            faker, surname, surname, recursion=recursion + 1
        )

    @classmethod
    def buildData(cls, schema: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Input: a Marshmallow schema
        Output: a dictionary of random data
        """
        data: Dict[str, Any] = {}
        for d in schema:

            assert "key" in d
            assert "type" in d

            key = d.get("key")
            field_type = d.get("type")

            assert key is not None
            assert field_type is not None

            if is_array := field_type.endswith("[]"):
                # py39:
                # field_type.removesuffix("[]")
                field_type = field_type[0:-2]

            if "options" in d:
                assert isinstance(d["options"], dict)
                if len(d["options"]) > 0:
                    keys = list(d["options"].keys())
                    if is_array:
                        data[key] = [cls.faker.random_element(keys)]
                    else:
                        data[key] = cls.faker.random_element(keys)
                # else:  # pragma: no cover
                #     pytest.fail(f"BuildData for {key}: invalid options (empty?)")
            elif field_type == "number" or field_type == "int":
                min_value = d.get("min", 0)
                max_value = d.get("max", 9999)
                data[key] = cls.faker.pyint(min_value=min_value, max_value=max_value)
            elif field_type == "date":

                min_date = None
                max_date = None

                if min_value := d.get("min"):
                    min_date = datetime.fromisoformat(min_value)

                if max_value := d.get("max"):
                    max_date = datetime.fromisoformat(max_value)

                random_date = cls.faker.date_time_between_dates(
                    datetime_start=min_date, datetime_end=max_date
                )
                data[key] = f"{random_date.isoformat()}.000Z"
            elif field_type == "email":
                data[key] = cls.faker.ascii_email()
            elif field_type == "boolean":
                data[key] = cls.faker.pybool()
            elif field_type == "password":
                data[key] = cls.faker.password(strong=True)
            elif field_type == "string":
                min_value = d.get("min")
                max_value = d.get("max")

                # No min/max validation
                if min_value is None and max_value is None:
                    min_value = 16
                    max_value = 32
                # Only min value provided
                elif max_value is None:
                    assert min_value is not None
                    # max(min_value, 1) is need in case of min_value == 0
                    max_value = max(min_value, 1) * 2
                # Only max value provided
                elif min_value is None:
                    assert max_value is not None
                    min_value = 1
                # Otherwise both min and max values provided => nothing to do

                data[key] = cls.faker.pystr(min_chars=min_value, max_chars=max_value)
            elif field_type == "nested":
                assert "schema" in d
                # build a sub-schema based on d["schema"]
                nested_data = cls.buildData(d["schema"])
                data[key] = orjson.dumps(nested_data).decode("UTF8")
            else:
                # Reached for example with lists of custom fields. In this case
                # the input can't be automatically set and here is simply ignored
                log.warning("BuildData for {}: unknow type {}", key, field_type)
                continue

            if is_array:  # i.e. the field type is anytype[]
                if not isinstance(data[key], list):
                    data[key] = [data[key]]

                # requests is unable to send lists, if not json-dumped
                data[key] = orjson.dumps(data[key]).decode("UTF8")

        return data

    @staticmethod
    def delete_mock_email(previous: bool = False) -> None:
        target = "prevsent" if previous else "lastsent"
        fpath = LOGS_FOLDER.joinpath(f"mock.mail.{target}.json")
        fpath.unlink(missing_ok=True)

    @staticmethod
    def read_mock_email(previous: bool = False) -> MockedEmail:
        target = "prevsent" if previous else "lastsent"
        fpath = LOGS_FOLDER.joinpath(f"mock.mail.{target}.json")
        if not fpath.exists():
            raise FileNotFoundError(fpath)

        with open(fpath) as file:
            data = cast(MockedEmail, orjson.loads(file.read()))

        if "msg" in data:
            tokens = data["msg"].split("\n\n")
            data["headers"] = tokens[0]
            data["body"] = "".join(tokens[1:])

        # Longer email are base64 encoded
        if "Content-Transfer-Encoding: base64" in data["body"]:  # pragma: no cover
            encodings = data["body"].split("Content-Transfer-Encoding: base64")
            # Get the last message... should the be the html content
            # A proper email parser would be need to improve this part
            base64_body = re.sub(r"--===============.*$", "", encodings[-1])
            base64_body = base64_body.replace("\n", "")

            # b64decode gives as output bytes, decode("utf-8") needed to get a string
            data["body"] = base64.b64decode(base64_body).decode("utf-8")

        fpath.unlink()
        return data

    @staticmethod
    def get_token_from_body(body: str) -> Optional[str]:
        token = None

        # if a token is not found the email is considered to be plain text
        # Emails are always html now
        if "</a>" not in body:  # pragma: no cover
            token = body[1 + body.rfind("/") :]
        # if a token is found the email is considered to be html
        else:
            urls = re.findall(
                r'href=["|\'](https?://[^\s<>"]+|www\.[^\s<>"]+)["|\']', body
            )

            log.warning("Found urls: {}", urls)
            if urls:
                for url in urls:
                    frontend_host = get_frontend_url()
                    # Search the first url that contains the frontend host,
                    # to skip any external url
                    if frontend_host in url:
                        # token is the last part of the url, extract as a path
                        token = Path(url).name
                        break

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
            secret = open(JWT_SECRET_FILE, "rb").read()

        if wrong_algorithm:
            algorithm = "HS256"
        else:
            algorithm = BaseAuthentication.JWT_ALGO

        if user_id is None:
            user_id = str(uuid.uuid4())

        payload: Dict[str, Any] = {"user_id": user_id, "jti": str(uuid.uuid4())}
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

        return jwt.encode(payload, secret, algorithm=algorithm)

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

        fpath = LOGS_FOLDER.joinpath("security-events.log")
        if not fpath.exists():  # pragma: no cover
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

                payload = orjson.loads(" ".join(tokens[8:])) if len(tokens) >= 9 else {}

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
                    # Target ID or empty
                    tokens[7] if len(tokens) >= 8 else "",
                    # Payload dictionary
                    payload,
                )

                if filters and not cls.event_matches_filters(event, filters):
                    continue

                events.append(event)

        events.reverse()
        return events

    @staticmethod
    def send_task(app: Flask, task_name: str, *args: Any, **kwargs: Any) -> Any:

        c = celery.get_instance()
        c.app = app

        # Celery type hints are wrong!?
        # Mypy complains about: error: "Callable[[], Any]" has no attribute "get"
        # But .tasks is a TaskRegistry and it is child of dict...
        # so that .get is totally legit!
        task = c.celery_app.tasks.get(task_name)

        if not task:
            raise AttributeError("Task not found")

        with execute_from_code_dir():
            return task(*args, **kwargs)
