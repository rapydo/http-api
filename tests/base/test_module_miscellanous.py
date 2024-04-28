import os
import tempfile
import time
from datetime import date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Optional, Union

import psutil
import pytest
from faker import Faker
from marshmallow.exceptions import ValidationError

from restapi.config import (
    DOMAIN,
    PRODUCTION,
    get_backend_url,
    get_frontend_url,
    get_host_type,
)
from restapi.connectors.smtp.notifications import get_html_template
from restapi.decorators import inject_callback_parameters, match_types
from restapi.env import Env
from restapi.exceptions import (
    BadRequest,
    Conflict,
    Forbidden,
    NotFound,
    RestApiException,
    ServerError,
    ServiceUnavailable,
    Unauthorized,
)
from restapi.models import Schema, fields
from restapi.rest.definition import EndpointResource
from restapi.rest.response import ResponseMaker, jsonifier
from restapi.services.uploader import Uploader
from restapi.tests import BaseTests
from restapi.utilities.configuration import load_yaml_file, mix
from restapi.utilities.logs import handle_log_output, obfuscate_dict
from restapi.utilities.meta import Meta
from restapi.utilities.processes import (
    Timeout,
    find_process,
    start_timeout,
    stop_timeout,
    wait_socket,
)
from restapi.utilities.time import get_timedelta, seconds_to_human


class TestApp(BaseTests):
    # #######################################
    # ####      Env
    #########################################
    def test_env(self, faker: Faker) -> None:
        assert not Env.to_bool(None)
        assert Env.to_bool(None, True)
        assert not Env.to_bool(False)
        assert Env.to_bool(True)
        assert not Env.to_bool(0)
        assert Env.to_bool(1)
        assert Env.to_bool(1 + faker.pyint())
        assert Env.to_bool(-faker.pyint() - 1)
        assert not Env.to_bool("")
        assert not Env.to_bool("false")
        assert not Env.to_bool("False")
        assert not Env.to_bool("FALSE")
        assert Env.to_bool("true")
        assert Env.to_bool("True")
        assert Env.to_bool("TRUE")
        assert Env.to_bool(faker.pystr())
        assert not Env.to_bool(object)
        assert Env.to_bool(object, True)

        random_default = faker.pyint()
        assert Env.to_int(None) == 0
        assert Env.to_int(None, random_default) == random_default
        assert Env.to_int(random_default) == random_default
        assert Env.to_int("42") == 42
        assert Env.to_int("-42") == -42
        assert Env.to_int(str(random_default)) == random_default
        assert Env.to_int(faker.pystr()) == 0
        assert Env.to_int(faker.pystr(), random_default) == random_default
        assert Env.to_bool(object) == 0

        prefix = faker.pystr().lower()
        var1 = faker.pystr()
        var2 = faker.pystr().lower()
        var3 = faker.pystr().upper()
        val1 = faker.pystr()
        val2 = faker.pystr()
        val3 = faker.pystr()

        os.environ[f"{prefix}_{var1}"] = val1
        os.environ[f"{prefix}_{var2}"] = val2
        os.environ[f"{prefix}_{var3}"] = val3
        variables = Env.load_variables_group(prefix)
        assert variables is not None
        assert isinstance(variables, dict)
        assert len(variables) == 3
        assert var2 in variables
        assert var3 not in variables
        assert var3.lower() in variables
        assert variables.get(var1.lower()) == val1
        assert variables.get(var2.lower()) == val2
        assert variables.get(var3.lower()) == val3

    # #######################################
    # ####      Responses
    #########################################
    def test_responses(self, faker: Faker) -> None:
        class MySchema(Schema):
            name = fields.Str()

        f = "myfield"
        assert (
            ResponseMaker.get_schema_type(f, fields.Str(metadata={"password": True}))
            == "password"
        )
        assert ResponseMaker.get_schema_type(f, fields.Bool()) == "boolean"
        assert ResponseMaker.get_schema_type(f, fields.Boolean()) == "boolean"
        assert ResponseMaker.get_schema_type(f, fields.Date()) == "date"
        assert ResponseMaker.get_schema_type(f, fields.DateTime()) == "datetime"
        assert ResponseMaker.get_schema_type(f, fields.AwareDateTime()) == "datetime"
        assert ResponseMaker.get_schema_type(f, fields.NaiveDateTime()) == "datetime"
        assert ResponseMaker.get_schema_type(f, fields.Decimal()) == "number"
        assert ResponseMaker.get_schema_type(f, fields.Email()) == "email"
        assert ResponseMaker.get_schema_type(f, fields.Float()) == "number"
        assert ResponseMaker.get_schema_type(f, fields.Int()) == "int"
        assert ResponseMaker.get_schema_type(f, fields.Integer()) == "int"
        assert ResponseMaker.get_schema_type(f, fields.Number()) == "number"
        assert ResponseMaker.get_schema_type(f, fields.Str()) == "string"
        assert ResponseMaker.get_schema_type(f, fields.String()) == "string"
        assert ResponseMaker.get_schema_type(f, fields.Dict()) == "dictionary"
        assert ResponseMaker.get_schema_type(f, fields.List(fields.Str())) == "string[]"
        assert ResponseMaker.get_schema_type(f, fields.Nested(MySchema())) == "nested"
        # Unsupported types, fallback to string
        assert ResponseMaker.get_schema_type(f, fields.URL()) == "string"
        assert ResponseMaker.get_schema_type(f, fields.Url()) == "string"
        assert ResponseMaker.get_schema_type(f, fields.UUID()) == "string"
        # assert ResponseMaker.get_schema_type(f, fields.Constant("x")) == "string"
        assert ResponseMaker.get_schema_type(f, fields.Field()) == "string"
        # assert ResponseMaker.get_schema_type(f, fields.Function()) == "string"
        # assert ResponseMaker.get_schema_type(f, fields.Mapping()) == "string"
        # assert ResponseMaker.get_schema_type(f, fields.Method()) == "string"
        # assert ResponseMaker.get_schema_type(f, fields.Raw()) == "string"
        # assert ResponseMaker.get_schema_type(f, fields.TimeDelta()) == "string"

        assert not ResponseMaker.is_binary(None)
        assert not ResponseMaker.is_binary("")
        assert not ResponseMaker.is_binary("application/json")
        assert ResponseMaker.is_binary("application/octet-stream")
        assert ResponseMaker.is_binary("application/x-bzip")
        assert ResponseMaker.is_binary("application/x-bzip2")
        assert ResponseMaker.is_binary("application/pdf")
        assert ResponseMaker.is_binary("application/msword")
        assert ResponseMaker.is_binary("application/rtf")
        assert ResponseMaker.is_binary("application/x-tar")
        assert ResponseMaker.is_binary("application/gzip")
        assert ResponseMaker.is_binary("application/zip")
        assert ResponseMaker.is_binary("application/x-7z-compressed")
        assert not ResponseMaker.is_binary("text/plain")
        assert not ResponseMaker.is_binary("text/css")
        assert not ResponseMaker.is_binary("text/csv")
        assert not ResponseMaker.is_binary("text/html")
        assert not ResponseMaker.is_binary("text/javascript")
        assert not ResponseMaker.is_binary("text/xml")
        assert ResponseMaker.is_binary("image/gif")
        assert ResponseMaker.is_binary("image/jpeg")
        assert ResponseMaker.is_binary("image/png")
        assert ResponseMaker.is_binary("image/svg+xml")
        assert ResponseMaker.is_binary("image/tiff")
        assert ResponseMaker.is_binary("image/webp")
        assert ResponseMaker.is_binary("image/bmp")
        assert ResponseMaker.is_binary("image/aac")
        assert ResponseMaker.is_binary("audio/midi")
        assert ResponseMaker.is_binary("audio/mpeg")
        assert ResponseMaker.is_binary("audio/wav")
        assert ResponseMaker.is_binary("audio/anyother")
        assert ResponseMaker.is_binary("video/mpeg")
        assert ResponseMaker.is_binary("video/ogg")
        assert ResponseMaker.is_binary("video/webm")
        assert ResponseMaker.is_binary("video/anyother")
        assert ResponseMaker.is_binary("video/anyother")
        assert not ResponseMaker.is_binary(faker.pystr())

        response = EndpointResource.response("", code=200)
        assert response[1] == 200  # type: ignore
        response = EndpointResource.response(None, code=200)
        assert response[1] == 204  # type: ignore
        response = EndpointResource.response(None, code=200, head_method=True)
        assert response[1] == 200  # type: ignore

    def test_jsonifier(self) -> None:
        assert jsonifier("x") == '"x"'
        assert jsonifier("1") == '"1"'
        assert jsonifier(1) == "1"
        assert jsonifier(1.2) == "1.2"
        assert jsonifier(Decimal("1.2")) == "1.2"
        assert jsonifier(["x"]) == '["x"]'
        assert jsonifier({"x"}) == '["x"]'
        assert jsonifier(("x",)) == '["x"]'
        assert jsonifier(Path("test")) == '"test"'
        assert jsonifier(date(2023, 1, 21)) == '"2023-01-21"'
        assert jsonifier(datetime(2023, 1, 21, 11, 34, 21)) == '"2023-01-21T11:34:21"'

    # #######################################
    # ####      Meta
    #########################################
    def test_meta(self) -> None:
        # This is a valid package containing other packages... but no task will be found
        tasks = Meta.get_celery_tasks("restapi.utilities")
        assert isinstance(tasks, list)
        assert len(tasks) == 0

        tasks = Meta.get_celery_tasks("this-should-not-exist")
        assert isinstance(tasks, list)
        assert len(tasks) == 0

        mcls = Meta.get_classes_from_module("this-should-not-exist")  # type: ignore
        assert isinstance(mcls, dict)
        assert len(mcls) == 0

        assert Meta.get_class("this-should-not-exist", "this-should-not-exist") is None
        assert Meta.get_class("initialization", "this-should-not-exist") is None
        assert Meta.get_class("initialization", "Initializer") is not None

        assert not Meta.get_module_from_string("this-should-not-exist")

        with pytest.raises(ModuleNotFoundError):
            Meta.get_module_from_string(
                "this-should-not-exist",
                exit_on_fail=True,
            )

        # This method is not very robust... but... let's test the current implementation
        # It basicaly return the first args if it is an instance of some classes
        assert not Meta.get_self_reference_from_args()
        selfref = Meta.get_self_reference_from_args("test")
        assert selfref == "test"

        models = Meta.import_models("this-should", "not-exist", mandatory=False)
        assert isinstance(models, dict)
        assert len(models) == 0

        with pytest.raises(SystemExit):
            Meta.import_models("this-should", "not-exist", mandatory=True)

        # Check exit_on_fail default value
        models = Meta.import_models("this-should", "not-exist")
        assert isinstance(models, dict)
        assert len(models) == 0

    # #######################################
    # ####      Templates
    #########################################
    def test_templates(self) -> None:
        h, p = get_html_template("this-should-not-exist", {})
        assert h is None
        assert p is None

    # #######################################
    # ####      Config Utilities
    #########################################
    def test_conf_utilities(self, faker: Faker) -> None:
        assert get_host_type("backend-server") == "backend-server"
        assert get_host_type("docs-generation") == "docs-generation"
        assert get_host_type("celery") == "celery"
        assert get_host_type("celery-beat") == "celery-beat"
        assert get_host_type("flower") == "flower"
        assert get_host_type("whateverelse") == "celery"
        assert get_host_type(faker.pystr()) == "celery"

    def test_get_backend_url(self) -> None:
        # bypass the lru_cache decorator
        func = get_backend_url.__wrapped__

        if PRODUCTION:
            assert func() == f"https://{DOMAIN}"
        else:
            assert func() == f"http://{DOMAIN}:8080"

        os.environ["FLASK_PORT"] = "1234"
        Env.get.cache_clear()

        if PRODUCTION:
            assert func() == f"https://{DOMAIN}"
        else:
            assert func() == f"http://{DOMAIN}:1234"

        os.environ["BACKEND_URL"] = "http://mydomain/xyz"
        Env.get.cache_clear()

        if PRODUCTION:
            assert func() == "http://mydomain/xyz"
        else:
            assert func() == "http://mydomain/xyz"

        os.environ["BACKEND_PREFIX"] = "abc"
        Env.get.cache_clear()

        if PRODUCTION:
            assert func() == "http://mydomain/xyz"
        else:
            assert func() == "http://mydomain/xyz"

        os.environ["BACKEND_URL"] = ""
        Env.get.cache_clear()

        if PRODUCTION:
            assert func() == f"https://{DOMAIN}/abc"
        else:
            assert func() == f"http://{DOMAIN}/abc:1234"

        os.environ["FLASK_PORT"] = "8080"
        os.environ["BACKEND_PREFIX"] = ""
        Env.get.cache_clear()

        if PRODUCTION:
            assert func() == f"https://{DOMAIN}"
        else:
            assert func() == f"http://{DOMAIN}:8080"

        os.environ["BACKEND_PREFIX"] = "/"
        Env.get.cache_clear()

        if PRODUCTION:
            assert func() == f"https://{DOMAIN}"
        else:
            assert func() == f"http://{DOMAIN}:8080"

        os.environ["BACKEND_PREFIX"] = "abc/"
        Env.get.cache_clear()

        if PRODUCTION:
            assert func() == f"https://{DOMAIN}/abc"
        else:
            assert func() == f"http://{DOMAIN}/abc:8080"

        os.environ["BACKEND_PREFIX"] = "/abc/"
        Env.get.cache_clear()

        if PRODUCTION:
            assert func() == f"https://{DOMAIN}/abc"
        else:
            assert func() == f"http://{DOMAIN}/abc:8080"

        os.environ["BACKEND_PREFIX"] = "///abc//"
        Env.get.cache_clear()

        if PRODUCTION:
            assert func() == f"https://{DOMAIN}/abc"
        else:
            assert func() == f"http://{DOMAIN}/abc:8080"

    def test_get_frontend_url(self) -> None:
        # bypass the lru_cache decorator
        func = get_frontend_url.__wrapped__

        if PRODUCTION:
            assert func() == f"https://{DOMAIN}"
        else:
            assert func() == f"http://{DOMAIN}"

        os.environ["FRONTEND_URL"] = "http://mydomain/xyz"
        Env.get.cache_clear()

        if PRODUCTION:
            assert func() == "http://mydomain/xyz"
        else:
            assert func() == "http://mydomain/xyz"

        os.environ["FRONTEND_PREFIX"] = "abc"
        Env.get.cache_clear()

        if PRODUCTION:
            assert func() == "http://mydomain/xyz"
        else:
            assert func() == "http://mydomain/xyz"

        os.environ["FRONTEND_URL"] = ""
        Env.get.cache_clear()

        if PRODUCTION:
            assert func() == f"https://{DOMAIN}/abc"
        else:
            assert func() == f"http://{DOMAIN}/abc"

        os.environ["FRONTEND_PREFIX"] = ""
        Env.get.cache_clear()

        if PRODUCTION:
            assert func() == f"https://{DOMAIN}"
        else:
            assert func() == f"http://{DOMAIN}"

        os.environ["FRONTEND_PREFIX"] = "/"
        Env.get.cache_clear()

        if PRODUCTION:
            assert func() == f"https://{DOMAIN}"
        else:
            assert func() == f"http://{DOMAIN}"

        os.environ["FRONTEND_PREFIX"] = "abc/"
        Env.get.cache_clear()

        if PRODUCTION:
            assert func() == f"https://{DOMAIN}/abc"
        else:
            assert func() == f"http://{DOMAIN}/abc"

        os.environ["FRONTEND_PREFIX"] = "/abc/"
        Env.get.cache_clear()

        if PRODUCTION:
            assert func() == f"https://{DOMAIN}/abc"
        else:
            assert func() == f"http://{DOMAIN}/abc"

        os.environ["FRONTEND_PREFIX"] = "///abc//"
        Env.get.cache_clear()

        if PRODUCTION:
            assert func() == f"https://{DOMAIN}/abc"
        else:
            assert func() == f"http://{DOMAIN}/abc"

    # #######################################
    # ####      Timeouts
    #########################################
    def test_timeouts(self) -> None:
        start_timeout(1)
        with pytest.raises(Timeout, match=r"Operation timeout: interrupted"):
            # This operation will be interrupted because slower than timeout
            time.sleep(2)

        start_timeout(1)
        try:
            stop_timeout()
            # This operation will not be interrupted
            time.sleep(2)
        except Exception:  # pragma: no cover
            pytest.fail("Operation interrupted")

    # #######################################
    # ####      Logging
    #########################################
    def test_logging(self) -> None:
        log_output = handle_log_output(None)
        assert isinstance(log_output, dict)
        assert len(log_output) == 0

        log_output = handle_log_output(" ")
        assert isinstance(log_output, dict)
        assert len(log_output) == 0

        assert handle_log_output(1) == 1

        # obfuscate_dict only accepts dict
        assert obfuscate_dict(None) is None  # type: ignore
        assert obfuscate_dict(10) == 10  # type: ignore
        assert obfuscate_dict(["x"]) == ["x"]  # type: ignore
        assert len(obfuscate_dict({})) == 0
        assert obfuscate_dict({"x": "y"}) == {"x": "y"}
        assert obfuscate_dict({"password": "y"}) == {"password": "****"}
        assert obfuscate_dict({"pwd": "y"}) == {"pwd": "****"}
        assert obfuscate_dict({"token": "y"}) == {"token": "****"}
        assert obfuscate_dict({"access_token": "y"}) == {"access_token": "****"}
        assert obfuscate_dict({"file": "y"}) == {"file": "****"}
        assert obfuscate_dict({"filename": "y"}) == {"filename": "****"}
        assert obfuscate_dict({"new_password": "y"}) == {"new_password": "****"}
        assert obfuscate_dict({"password_confirm": "y"}) == {"password_confirm": "****"}

    # #######################################
    # ####      YAML data load and mix
    #########################################
    def test_yaml(self) -> None:
        data: dict[str, Any] = {"a": 1}
        assert mix({}, data) == data

        data1: dict[str, Any] = {"a": {"b": 1}, "c": 1}
        data2: dict[str, Any] = {"a": {"b": 2}}
        expected: dict[str, Any] = {"a": {"b": 2}, "c": 1}

        assert mix(data1, data2) == expected

        data1 = {"a": {"b": 1}, "c": 1}
        data2 = {"a": None}
        # Cannot replace with an empty list
        assert mix(data1, data2) == data1

        data1 = {"a": [1, 2]}
        data2 = {"a": [3, 4]}
        expected = {"a": [1, 2, 3, 4]}

        assert mix(data1, data2) == expected

        # Invalid file / path
        with pytest.raises(AttributeError):
            load_yaml_file(Path("path", "invalid"))

        with pytest.raises(AttributeError):
            load_yaml_file(Path("tests", "invalid"))

        # Valid path, but not in yaml format
        with pytest.raises(AttributeError):
            load_yaml_file(Path("tests", "conftest.py"))

        # File is empty
        tmpf = tempfile.NamedTemporaryFile()
        with pytest.raises(AttributeError):
            load_yaml_file(Path(tmpf.name))
        tmpf.close()

    # #######################################
    # ####      Uploader
    #########################################
    def test_uploader(self) -> None:
        meta = Uploader.get_file_metadata("invalid_file")  # type: ignore
        assert isinstance(meta, dict)
        assert len(meta) == 0

        metadata_file_path = "confs/projects_defaults.yaml"
        meta = Uploader.get_file_metadata(metadata_file_path)  # type: ignore
        assert isinstance(meta, dict)
        assert len(meta) == 2
        assert "type" in meta
        assert "charset" in meta
        assert meta["type"] == "text/plain"
        assert meta["charset"] == "utf-8"

        meta = Uploader.get_file_metadata(Path("invalid_file"))
        assert isinstance(meta, dict)
        assert len(meta) == 0

        meta = Uploader.get_file_metadata(Path("confs/projects_defaults.yaml"))
        assert isinstance(meta, dict)
        assert len(meta) == 2
        assert "type" in meta
        assert "charset" in meta
        assert meta["type"] == "text/plain"
        assert meta["charset"] == "utf-8"

        # t = total_length
        # s = start
        # e = end
        tlen, start, end = Uploader.parse_content_range(None)
        assert tlen is None
        assert start is None
        assert end is None

        tlen, start, end = Uploader.parse_content_range("")
        assert tlen is None
        assert start is None
        assert end is None

        tlen, start, end = Uploader.parse_content_range("test")
        assert tlen is None
        assert start is None
        assert end is None

        tlen, start, end = Uploader.parse_content_range("test/test")
        assert tlen is None
        assert start is None
        assert end is None

        tlen, start, end = Uploader.parse_content_range("test/1000")
        assert tlen == 1000
        assert start == 0
        assert end == 1000

        tlen, start, end = Uploader.parse_content_range("bytes test/1000")
        assert tlen == 1000
        assert start == 0
        assert end == 1000

        tlen, start, end = Uploader.parse_content_range("bytes */1000")
        assert tlen == 1000
        assert start == 0
        assert end == 1000

        tlen, start, end = Uploader.parse_content_range("bytes 2-499/1000")
        assert tlen == 1000
        assert start == 2
        assert end == 500

        tlen, start, end = Uploader.parse_content_range("bytes 2-499*/1000")
        assert tlen == 1000
        assert start == 0
        assert end == 1000

        with pytest.raises(
            BadRequest, match=r"Invalid null byte in subfolder parameter"
        ):
            Uploader.validate_upload_folder(Path("\x00"))

        with pytest.raises(
            BadRequest, match=r"Invalid null byte in subfolder parameter"
        ):
            Uploader.validate_upload_folder(Path("/uploads/\x00"))

        with pytest.raises(
            BadRequest, match=r"Invalid null byte in subfolder parameter"
        ):
            Uploader.validate_upload_folder(Path("/uploads/AA\x00BB"))

        with pytest.raises(Forbidden, match=r"Invalid file path"):
            Uploader.validate_upload_folder(Path("/etc/"))

        with pytest.raises(Forbidden, match=r"Invalid file path"):
            Uploader.validate_upload_folder(Path("../../tmp/"))

    # #######################################
    # ####      Time
    #########################################
    def test_time(self, faker: Faker) -> None:
        every = faker.pyint()

        t = get_timedelta(every, "seconds")
        assert t is not None
        assert isinstance(t, timedelta)
        assert 86400 * t.days + t.seconds == every
        assert t.microseconds == 0

        t = get_timedelta(every, "days")
        assert t is not None
        assert isinstance(t, timedelta)
        assert t.days == every
        assert t.seconds == 0
        assert t.microseconds == 0

        t = get_timedelta(every, "microseconds")
        assert t is not None
        assert isinstance(t, timedelta)
        assert t.days == 0
        assert 1_000_000 * t.seconds + t.microseconds == every

        t = get_timedelta(every, "milliseconds")
        assert t is not None
        assert isinstance(t, timedelta)
        assert t.days == 0
        assert 1_000_000 * t.seconds + t.microseconds == every * 1000

        t = get_timedelta(every, "minutes")
        assert t is not None
        assert isinstance(t, timedelta)
        assert 86400 * t.days + t.seconds == every * 60
        assert t.microseconds == 0

        t = get_timedelta(every, "hours")
        assert t is not None
        assert isinstance(t, timedelta)
        assert 86400 * t.days + t.seconds == every * 3600
        assert t.microseconds == 0

        t = get_timedelta(every, "weeks")
        assert t is not None
        assert isinstance(t, timedelta)
        assert t.days == every * 7
        assert t.seconds == 0
        assert t.microseconds == 0

        with pytest.raises(BadRequest):
            get_timedelta(every, "months")  # type: ignore

        with pytest.raises(BadRequest):
            get_timedelta(every, "years")  # type: ignore

        with pytest.raises(BadRequest):
            get_timedelta(every, faker.pystr())

        assert seconds_to_human(0) == "0 seconds"
        assert seconds_to_human(1) == "1 second"
        assert seconds_to_human(2) == "2 seconds"
        assert seconds_to_human(59) == "59 seconds"
        assert seconds_to_human(60) == "1 minute"
        assert seconds_to_human(61) == "1 minute, 1 second"
        assert seconds_to_human(62) == "1 minute, 2 seconds"
        assert seconds_to_human(119) == "1 minute, 59 seconds"
        assert seconds_to_human(120) == "2 minutes"
        assert seconds_to_human(121) == "2 minutes, 1 second"
        assert seconds_to_human(122) == "2 minutes, 2 seconds"
        assert seconds_to_human(179) == "2 minutes, 59 seconds"
        assert seconds_to_human(532) == "8 minutes, 52 seconds"
        assert seconds_to_human(3600) == "1 hour"
        assert seconds_to_human(3601) == "1 hour, 0 minutes, 1 second"
        assert seconds_to_human(3602) == "1 hour, 0 minutes, 2 seconds"
        assert seconds_to_human(3660) == "1 hour, 1 minute"
        assert seconds_to_human(3661) == "1 hour, 1 minute, 1 second"
        assert seconds_to_human(3662) == "1 hour, 1 minute, 2 seconds"
        assert seconds_to_human(3720) == "1 hour, 2 minutes"
        assert seconds_to_human(7200) == "2 hours"
        assert seconds_to_human(82800) == "23 hours"
        assert seconds_to_human(86399) == "23 hours, 59 minutes, 59 seconds"
        assert seconds_to_human(86400) == "1 day"
        assert seconds_to_human(86401) == "1 day, 0 hours, 0 minutes, 1 second"
        assert seconds_to_human(86402) == "1 day, 0 hours, 0 minutes, 2 seconds"
        assert seconds_to_human(86460) == "1 day, 0 hours, 1 minute"
        assert seconds_to_human(86461) == "1 day, 0 hours, 1 minute, 1 second"
        assert seconds_to_human(86520) == "1 day, 0 hours, 2 minutes"
        assert seconds_to_human(86521) == "1 day, 0 hours, 2 minutes, 1 second"
        assert seconds_to_human(86522) == "1 day, 0 hours, 2 minutes, 2 seconds"
        assert seconds_to_human(90000) == "1 day, 1 hour"
        assert seconds_to_human(90060) == "1 day, 1 hour, 1 minute"
        assert seconds_to_human(90061) == "1 day, 1 hour, 1 minute, 1 second"
        assert seconds_to_human(90062) == "1 day, 1 hour, 1 minute, 2 seconds"
        assert seconds_to_human(90120) == "1 day, 1 hour, 2 minutes"
        assert seconds_to_human(90121) == "1 day, 1 hour, 2 minutes, 1 second"
        assert seconds_to_human(90122) == "1 day, 1 hour, 2 minutes, 2 seconds"
        assert seconds_to_human(93600) == "1 day, 2 hours"
        assert seconds_to_human(777600) == "9 days"
        assert seconds_to_human(10627200) == "123 days"
        assert seconds_to_human(22222222) == "257 days, 4 hours, 50 minutes, 22 seconds"
        assert seconds_to_human(63072000) == "730 days"

    # #######################################
    # ####      Exceptions
    #########################################
    def test_exceptions(self) -> None:
        with pytest.raises(RestApiException) as e:
            raise BadRequest("test")
        assert e.value.status_code == 400

        with pytest.raises(RestApiException) as e:
            raise Unauthorized("test")
        assert e.value.status_code == 401

        with pytest.raises(RestApiException) as e:
            raise Forbidden("test")
        assert e.value.status_code == 403

        with pytest.raises(RestApiException) as e:
            raise NotFound("test")
        assert e.value.status_code == 404

        with pytest.raises(RestApiException) as e:
            raise Conflict("test")
        assert e.value.status_code == 409

        with pytest.raises(RestApiException) as e:
            raise ServerError("test")
        assert e.value.status_code == 500

        with pytest.raises(RestApiException) as e:
            raise ServiceUnavailable("test")
        assert e.value.status_code == 503

    def test_marshmallow_schemas(self) -> None:
        class Input1(Schema):
            # Note: This is a replacement of the normal DelimitedList defined by rapydo
            unique_delimited_list = fields.DelimitedList(
                fields.Str(), delimiter=",", required=True, unique=True
            )
            # Note: This is a replacement of the normal List list defined by rapydo
            advanced_list = fields.List(
                fields.Str(),
                required=True,
                unique=True,
                min_items=2,
            )

        schema = Input1(strip_required=False)
        with pytest.raises(ValidationError) as e:
            schema.load({})
            pytest.fail("No exception raised")  # pragma: no cover
        assert isinstance(e.value.messages, dict)
        assert "advanced_list" in e.value.messages
        err = "Missing data for required field."
        assert e.value.messages["advanced_list"][0] == err
        assert "unique_delimited_list" in e.value.messages
        assert e.value.messages["unique_delimited_list"][0] == err

        schema = Input1(strip_required=True)
        # ValidationError error is not raised because required is stripped of
        assert len(schema.load({})) == 0

        with pytest.raises(ValidationError) as e:
            schema.load({"advanced_list": None})
        assert isinstance(e.value.messages, dict)
        assert "advanced_list" in e.value.messages
        assert e.value.messages["advanced_list"][0] == "Field may not be null."

        with pytest.raises(ValidationError) as e:
            schema.load({"advanced_list": ""})
        assert isinstance(e.value.messages, dict)
        assert "advanced_list" in e.value.messages
        assert e.value.messages["advanced_list"][0] == "Not a valid list."

        with pytest.raises(ValidationError) as e:
            schema.load({"advanced_list": [10]})
        assert isinstance(e.value.messages, dict)
        assert "advanced_list" in e.value.messages
        assert 0 in e.value.messages["advanced_list"]
        assert e.value.messages["advanced_list"][0][0] == "Not a valid string."

        min_items_error = "Expected at least 2 items, received 1"
        with pytest.raises(ValidationError) as e:
            schema.load({"advanced_list": ["a"]})
        assert isinstance(e.value.messages, dict)
        assert "advanced_list" in e.value.messages
        assert e.value.messages["advanced_list"][0] == min_items_error

        with pytest.raises(ValidationError) as e:
            schema.load({"advanced_list": ["a", "a"]})
        assert isinstance(e.value.messages, dict)
        assert "advanced_list" in e.value.messages
        assert e.value.messages["advanced_list"][0] == min_items_error

        r = schema.load({"advanced_list": ["a", "a", "b"]})
        assert "advanced_list" in r
        assert len(r["advanced_list"]) == 2

        with pytest.raises(ValidationError) as e:
            schema.load({"advanced_list": {"a": "b"}})
        assert isinstance(e.value.messages, dict)
        assert "advanced_list" in e.value.messages
        assert e.value.messages["advanced_list"][0] == "Not a valid list."

        r = schema.load({"unique_delimited_list": ""})
        assert "unique_delimited_list" in r
        # This is because I added a check to return value if value is ""
        assert len(r["unique_delimited_list"]) == 0
        # assert len(r["unique_delimited_list"]) == 1
        # assert r["unique_delimited_list"][0] == ""

        r = schema.load({"unique_delimited_list": "xyz"})
        assert "unique_delimited_list" in r
        assert len(r["unique_delimited_list"]) == 1
        assert r["unique_delimited_list"][0] == "xyz"

        r = schema.load({"unique_delimited_list": "a,b"})
        assert "unique_delimited_list" in r
        assert len(r["unique_delimited_list"]) == 2
        assert r["unique_delimited_list"][0] == "a"
        assert r["unique_delimited_list"][1] == "b"

        r = schema.load({"unique_delimited_list": "a,b,c"})
        assert "unique_delimited_list" in r
        assert len(r["unique_delimited_list"]) == 3
        assert r["unique_delimited_list"][0] == "a"
        assert r["unique_delimited_list"][1] == "b"
        assert r["unique_delimited_list"][2] == "c"

        with pytest.raises(ValidationError) as e:
            schema.load({"unique_delimited_list": "a,b,b"})
        assert isinstance(e.value.messages, dict)
        assert "unique_delimited_list" in e.value.messages
        err = "Input list contains duplicates"
        assert e.value.messages["unique_delimited_list"][0] == err

        # No strips on elements
        r = schema.load({"unique_delimited_list": "a,b, c"})
        assert "unique_delimited_list" in r
        assert len(r["unique_delimited_list"]) == 3
        assert r["unique_delimited_list"][0] == "a"
        assert r["unique_delimited_list"][1] == "b"
        # assert r["unique_delimited_list"][2] == " c"
        # Now input is trimmed
        assert r["unique_delimited_list"][2] == "c"

        r = schema.load({"unique_delimited_list": "a,b,c "})
        assert "unique_delimited_list" in r
        assert len(r["unique_delimited_list"]) == 3
        assert r["unique_delimited_list"][0] == "a"
        assert r["unique_delimited_list"][1] == "b"
        # assert r["unique_delimited_list"][2] == "c "
        # Now input is trimmed
        assert r["unique_delimited_list"][2] == "c"

    def test_callbackend_parameters_injection(self, faker: Faker) -> None:
        # These functions are not executed => no cover
        def missing_endpoint() -> None:  # pragma: no cover
            pass

        # These functions are not executed => no cover
        def wrong_endpoint(endpoint: str) -> None:  # pragma: no cover
            pass

        # These functions are not executed => no cover
        def ok_endpoint_no_params(
            endpoint: EndpointResource,
        ) -> None:  # pragma: no cover
            pass

        # These functions are not executed => no cover
        def ok_endpoint_with_params(
            endpoint: EndpointResource, a: str, b: Faker
        ) -> None:  # pragma: no cover
            pass

        # Wrong callback: endpoint parameter is missing
        injected_parameters = inject_callback_parameters(missing_endpoint, {}, {})
        assert injected_parameters is None

        # Wrong callback: endpoint parameter is missing
        injected_parameters = inject_callback_parameters(
            missing_endpoint,
            {"endpoint": None},
            {"endpoint": None},
        )
        assert injected_parameters is None

        # Wrong callback: endpoint parameter has a wrong type
        injected_parameters = inject_callback_parameters(wrong_endpoint, {}, {})
        assert injected_parameters is None

        # Wrong callback: endpoint parameter has a wrong type
        injected_parameters = inject_callback_parameters(
            wrong_endpoint,
            {"endpoint": None},
            {"endpoint": None},
        )
        assert injected_parameters is None

        # Callback is good and takes no parameters
        injected_parameters = inject_callback_parameters(
            ok_endpoint_no_params,
            {},
            {},
        )
        assert injected_parameters is not None

        # Callback is good and takes no parameters
        injected_parameters = inject_callback_parameters(
            ok_endpoint_no_params,
            {"endpoint": None, "a": "abc"},
            {"b": "aaa"},
        )
        assert injected_parameters is not None

        # Starting from here the callback wants two parameters

        # Parameters not found in kwargs / view_args
        injected_parameters = inject_callback_parameters(
            ok_endpoint_with_params,
            {},
            {},
        )
        assert injected_parameters is None

        # Only one parameter found in kwargs / view_args
        injected_parameters = inject_callback_parameters(
            ok_endpoint_with_params,
            {"a": "abc"},
            {},
        )
        assert injected_parameters is None

        # Both parameters found in kwargs / view_args
        injected_parameters = inject_callback_parameters(
            ok_endpoint_with_params,
            {"a": "abc"},
            {"b": faker},
        )
        assert injected_parameters is not None

        # Both parameters found in kwargs / view_args
        injected_parameters = inject_callback_parameters(
            ok_endpoint_with_params,
            {"b": faker},
            {"a": "abc"},
        )
        assert injected_parameters is not None

        # Both parameters found in kwargs / view_args
        injected_parameters = inject_callback_parameters(
            ok_endpoint_with_params,
            {"a": "abc", "b": faker},
            {},
        )
        assert injected_parameters is not None

        # Both parameters found in kwargs / view_args
        injected_parameters = inject_callback_parameters(
            ok_endpoint_with_params,
            {},
            {"a": "abc", "b": faker},
        )
        assert injected_parameters is not None

        # Both parameters found but with wrong type (int instead of str)
        injected_parameters = inject_callback_parameters(
            ok_endpoint_with_params,
            {"a": 10, "b": faker},
            {},
        )
        assert injected_parameters is None

        # Both parameters found but with wrong type (str instead of Faker)
        injected_parameters = inject_callback_parameters(
            ok_endpoint_with_params,
            {"a": "abc", "b": "faker"},
            {},
        )
        assert injected_parameters is None

        # Both parameters found but with wrong type (None instead of Faker)
        injected_parameters = inject_callback_parameters(
            ok_endpoint_with_params,
            {"a": "abc", "b": None},
            {},
        )
        assert injected_parameters is None

        # Both parameters found but with wrong type (None instead of str)
        injected_parameters = inject_callback_parameters(
            ok_endpoint_with_params,
            {"a": None, "b": faker},
            {},
        )
        assert injected_parameters is None

        # Both parameters found but with wrong type (int instead of str)
        injected_parameters = inject_callback_parameters(
            ok_endpoint_with_params,
            {},
            {"a": 10, "b": faker},
        )
        assert injected_parameters is None

        # Both parameters found but with wrong type (str instead of Faker)
        injected_parameters = inject_callback_parameters(
            ok_endpoint_with_params,
            {},
            {"a": "abc", "b": "faker"},
        )
        assert injected_parameters is None

        # Both parameters found but with wrong type (None instead of Faker)
        injected_parameters = inject_callback_parameters(
            ok_endpoint_with_params,
            {},
            {"a": "abc", "b": None},
        )
        assert injected_parameters is None

        # Both parameters found but with wrong type (None instead of str)
        injected_parameters = inject_callback_parameters(
            ok_endpoint_with_params,
            {},
            {"a": None, "b": faker},
        )
        assert injected_parameters is None

        assert match_types(EndpointResource, EndpointResource)
        assert not match_types(EndpointResource, "EndpointResource")
        assert not match_types(EndpointResource, None)
        assert not match_types(EndpointResource, type(None))
        assert not match_types(EndpointResource, 1)
        assert not match_types(EndpointResource, True)
        assert not match_types(EndpointResource, False)
        assert not match_types(EndpointResource, int)
        assert not match_types(EndpointResource, [])
        assert not match_types(EndpointResource, {})
        assert not match_types(EndpointResource, ["test"])
        assert not match_types(EndpointResource, {"test": 1})

        assert match_types(Any, EndpointResource)
        assert match_types(Any, "EndpointResource")
        assert match_types(Any, None)
        assert match_types(Any, type(None))
        assert match_types(Any, 1)
        assert match_types(Any, True)
        assert match_types(Any, False)
        assert match_types(Any, int)
        assert match_types(Any, type([]))
        assert match_types(Any, type({}))
        assert match_types(Any, ["test"])
        assert match_types(Any, {"test": 1})

        assert not match_types(str, EndpointResource)
        assert match_types(str, "EndpointResource")
        assert not match_types(str, None)
        assert not match_types(str, 1)
        assert not match_types(str, True)
        assert not match_types(str, False)
        assert not match_types(str, [])
        assert not match_types(str, {})
        assert not match_types(str, ["test"])
        assert not match_types(str, {"test": 1})

        assert not match_types(Optional[str], EndpointResource)
        assert match_types(Optional[str], "EndpointResource")
        assert match_types(Optional[str], type(None))
        assert not match_types(Optional[str], 1)
        assert not match_types(Optional[str], [])
        assert not match_types(Optional[str], {})
        assert not match_types(Optional[str], ["test"])
        assert not match_types(Optional[str], {"test": 1})

        assert match_types(Union[str, int], 1)
        assert match_types(Union[str, int], "1")
        assert not match_types(Union[str, int], [])

        assert match_types(bool, True)
        assert match_types(bool, False)
        assert not match_types(bool, 0)
        assert not match_types(bool, 1)
        assert not match_types(bool, "...")
        assert not match_types(bool, [])
        assert not match_types(bool, [1])

        # please note the "not Union" that I added for a mistake
        # leading to a infinite recursion loop
        # before adding as specific case in match_types
        assert not match_types(not Union[str, int], [])

    # #######################################
    # ####      Processes
    #########################################
    def test_processes(self) -> None:
        assert not find_process("this-should-not-exist")
        assert find_process("restapi")
        assert find_process("dumb-init")
        # current process is not retrieved by find_process
        current_pid = os.getpid()
        process = psutil.Process(current_pid)
        assert not find_process(process.name())

        start_timeout(15)
        with pytest.raises(Timeout):
            wait_socket("invalid", 123, service_name="test")

        start_timeout(15)
        with pytest.raises(ServiceUnavailable):
            wait_socket("invalid", 123, service_name="test", retries=2)
