import os
import tempfile
import time
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict

import psutil
import pytest
from faker import Faker
from marshmallow.exceptions import ValidationError

from restapi.connectors.smtp.notifications import get_html_template
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
from restapi.rest.response import ResponseMaker
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
        assert ResponseMaker.get_schema_type(f, fields.Str(password=True)) == "password"
        assert ResponseMaker.get_schema_type(f, fields.Bool()) == "boolean"
        assert ResponseMaker.get_schema_type(f, fields.Boolean()) == "boolean"
        assert ResponseMaker.get_schema_type(f, fields.Date()) == "date"
        assert ResponseMaker.get_schema_type(f, fields.DateTime()) == "date"
        assert ResponseMaker.get_schema_type(f, fields.AwareDateTime()) == "date"
        assert ResponseMaker.get_schema_type(f, fields.NaiveDateTime()) == "date"
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

        assert not ResponseMaker.is_binary(None)  # type: ignore
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
        try:
            wait_socket("invalid", 123, service_name="test")
            pytest.fail("wait_socket should be blocking!")  # pragma: no cover
        except Timeout:
            pass

        start_timeout(15)
        try:
            wait_socket("invalid", 123, service_name="test", retries=2)
            pytest.fail("No exception raised")  # pragma: no cover
        except ServiceUnavailable:
            pass
        except Timeout:  # pragma: no cover
            pytest.fail("Reached Timeout, max retries not worked?")

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

        assert not Meta.get_module_from_string("this-should-not-exist")

        try:
            Meta.get_module_from_string(
                "this-should-not-exist",
                exit_on_fail=True,
            )
            pytest.fail("ModuleNotFoundError not raised")  # pragma: no cover
        except ModuleNotFoundError:
            pass

        # This method is not very robust... but... let's test the current implementation
        # It basicaly return the first args if it is an instance of some classes
        assert not Meta.get_self_reference_from_args()
        selfref = Meta.get_self_reference_from_args("test")
        assert selfref == "test"

        models = Meta.import_models("this-should", "not-exist", mandatory=False)
        assert isinstance(models, dict)
        assert len(models) == 0

        try:
            Meta.import_models("this-should", "not-exist", mandatory=True)
            pytest.fail("SystemExit not raised")  # pragma: no cover
        except SystemExit:
            pass

        # Check exit_on_fail default value
        models = Meta.import_models("this-should", "not-exist")
        assert isinstance(models, dict)
        assert len(models) == 0

        assert Meta.get_instance("invalid.path", "InvalidClass") is None
        assert Meta.get_instance("customization", "InvalidClass") is None
        assert Meta.get_instance("customization", "Customizer") is not None

    # #######################################
    # ####      Templates
    #########################################
    def test_templates(self) -> None:

        h, p = get_html_template("this-should-not-exist", {})
        assert h is None
        assert p is None

    # #######################################
    # ####      Timeouts
    #########################################
    def test_timeouts(self) -> None:

        start_timeout(1)
        try:
            # This operation will be interrupted because slower than timeout
            time.sleep(2)
            pytest.fail("Operation not interrupted")  # pragma: no cover
        except BaseException as e:
            assert str(e) == "Operation timeout: interrupted"

        start_timeout(1)
        try:
            stop_timeout()
            # This operation will not be interrupted
            time.sleep(2)
        except BaseException:  # pragma: no cover
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

        data: Dict[str, Any] = {"a": 1}
        assert mix({}, data) == data

        data1: Dict[str, Any] = {"a": {"b": 1}, "c": 1}
        data2: Dict[str, Any] = {"a": {"b": 2}}
        expected: Dict[str, Any] = {"a": {"b": 2}, "c": 1}

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
        try:
            load_yaml_file(Path("invalid"), Path("path"))
            pytest.fail("No exception raised")  # pragma: no cover
        except AttributeError:
            pass

        try:
            load_yaml_file(Path("invalid"), Path("tests"))
            pytest.fail("No exception raised")  # pragma: no cover
        except AttributeError:
            pass

        # Valid path, but not in yaml format
        try:
            load_yaml_file(Path("conftest.py"), Path("tests"))
            pytest.fail("No exception raised")  # pragma: no cover
        except AttributeError:
            pass

        # File is empty
        tmpf = tempfile.NamedTemporaryFile()
        try:
            load_yaml_file(Path(tmpf.name), Path("."))
            pytest.fail("No exception raised")  # pragma: no cover
        except AttributeError:
            pass
        tmpf.close()

    # #######################################
    # ####      Uploader
    #########################################
    def test_uploader(self) -> None:

        meta = Uploader.get_file_metadata("invalid_file")  # type: ignore
        assert isinstance(meta, dict)
        assert len(meta) == 0

        meta = Uploader.get_file_metadata("confs/projects_defaults.yaml")  # type: ignore
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

        try:
            get_timedelta(every, "months")  # type: ignore
            pytest.fail(
                "No exception raised from get_timedelta with period=months"
            )  # pragma: no cover
        except BadRequest:
            pass

        try:
            get_timedelta(every, "years")  # type: ignore
            pytest.fail(
                "No exception raised from get_timedelta with period=years"
            )  # pragma: no cover
        except BadRequest:
            pass

        try:
            get_timedelta(every, faker.pystr())  # type: ignore
            pytest.fail(
                "No exception raised from get_timedelta with period=randomstr"
            )  # pragma: no cover
        except BadRequest:
            pass

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
        assert seconds_to_human(532) == "8 minutes, 8 seconds"
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

        try:
            raise BadRequest("test")
        except RestApiException as e:
            assert e.status_code == 400

        try:
            raise Unauthorized("test")
        except RestApiException as e:
            assert e.status_code == 401

        try:
            raise Forbidden("test")
        except RestApiException as e:
            assert e.status_code == 403

        try:
            raise NotFound("test")
        except RestApiException as e:
            assert e.status_code == 404

        try:
            raise Conflict("test")
        except RestApiException as e:
            assert e.status_code == 409

        try:
            raise ServerError("test")
        except RestApiException as e:
            assert e.status_code == 500

        try:
            raise ServiceUnavailable("test")
        except RestApiException as e:
            assert e.status_code == 503

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
        try:
            schema.load({})
            pytest.fail("No exception raised")  # pragma: no cover
        except ValidationError as e:
            assert isinstance(e.messages, dict)
            assert "advanced_list" in e.messages
            err = "Missing data for required field."
            assert e.messages["advanced_list"][0] == err
            assert "unique_delimited_list" in e.messages
            assert e.messages["unique_delimited_list"][0] == err

        schema = Input1(strip_required=True)
        # ValidationError error is not raised because required is stripped of
        assert len(schema.load({})) == 0

        try:
            schema.load({"advanced_list": None})
            pytest.fail("No exception raised")  # pragma: no cover
        except ValidationError as e:
            assert isinstance(e.messages, dict)
            assert "advanced_list" in e.messages
            assert e.messages["advanced_list"][0] == "Field may not be null."

        try:
            schema.load({"advanced_list": ""})
            pytest.fail("No exception raised")  # pragma: no cover
        except ValidationError as e:
            assert isinstance(e.messages, dict)
            assert "advanced_list" in e.messages
            assert e.messages["advanced_list"][0] == "Not a valid list."

        try:
            schema.load({"advanced_list": [10]})
            pytest.fail("No exception raised")  # pragma: no cover
        except ValidationError as e:
            assert isinstance(e.messages, dict)
            assert "advanced_list" in e.messages
            assert 0 in e.messages["advanced_list"]
            assert e.messages["advanced_list"][0][0] == "Not a valid string."

        min_items_error = "Expected at least 2 items, received 1"
        try:
            schema.load({"advanced_list": ["a"]})
            pytest.fail("No exception raised")  # pragma: no cover
        except ValidationError as e:
            assert isinstance(e.messages, dict)
            assert "advanced_list" in e.messages
            assert e.messages["advanced_list"][0] == min_items_error

        try:
            schema.load({"advanced_list": ["a", "a"]})
            pytest.fail("No exception raised")  # pragma: no cover
        except ValidationError as e:
            assert isinstance(e.messages, dict)
            assert "advanced_list" in e.messages
            assert e.messages["advanced_list"][0] == min_items_error

        r = schema.load({"advanced_list": ["a", "a", "b"]})
        assert "advanced_list" in r
        assert len(r["advanced_list"]) == 2

        try:
            schema.load({"advanced_list": {"a": "b"}})
            pytest.fail("No exception raised")  # pragma: no cover
        except ValidationError as e:
            assert isinstance(e.messages, dict)
            assert "advanced_list" in e.messages
            assert e.messages["advanced_list"][0] == "Not a valid list."

        r = schema.load({"unique_delimited_list": ""})
        assert "unique_delimited_list" in r
        assert len(r["unique_delimited_list"]) == 1
        assert r["unique_delimited_list"][0] == ""

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

        try:
            schema.load({"unique_delimited_list": "a,b,b"})
            pytest.fail("No exception raised")  # pragma: no cover
        except ValidationError as e:
            assert isinstance(e.messages, dict)
            assert "unique_delimited_list" in e.messages
            err = "Input list contains duplicates"
            assert e.messages["unique_delimited_list"][0] == err

        # No strips on elements
        r = schema.load({"unique_delimited_list": "a,b, c"})
        assert "unique_delimited_list" in r
        assert len(r["unique_delimited_list"]) == 3
        assert r["unique_delimited_list"][0] == "a"
        assert r["unique_delimited_list"][1] == "b"
        assert r["unique_delimited_list"][2] == " c"

        r = schema.load({"unique_delimited_list": "a,b,c "})
        assert "unique_delimited_list" in r
        assert len(r["unique_delimited_list"]) == 3
        assert r["unique_delimited_list"][0] == "a"
        assert r["unique_delimited_list"][1] == "b"
        assert r["unique_delimited_list"][2] == "c "
