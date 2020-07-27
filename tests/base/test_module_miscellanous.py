import os
import tempfile
import time

import psutil
import pytest

from restapi.env import Env
from restapi.exceptions import ServiceUnavailable
from restapi.models import fields
from restapi.rest.response import ResponseMaker
from restapi.services.detect import detector
from restapi.services.uploader import Uploader
from restapi.tests import BaseTests
from restapi.utilities.configuration import load_yaml_file, mix
from restapi.utilities.htmlcodes import hcodes
from restapi.utilities.logs import handle_log_output, obfuscate_dict
from restapi.utilities.meta import Meta
from restapi.utilities.processes import (
    Timeout,
    find_process,
    start_timeout,
    stop_timeout,
    wait_socket,
)
from restapi.utilities.templates import get_html_template


class TestApp(BaseTests):
    def test_libs(self, faker):

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

        assert ResponseMaker.get_schema_type(fields.Str(password=True)) == "password"
        assert ResponseMaker.get_schema_type(fields.Bool()) == "boolean"
        assert ResponseMaker.get_schema_type(fields.Boolean()) == "boolean"
        assert ResponseMaker.get_schema_type(fields.Date()) == "date"
        assert ResponseMaker.get_schema_type(fields.DateTime()) == "date"
        assert ResponseMaker.get_schema_type(fields.AwareDateTime()) == "date"
        assert ResponseMaker.get_schema_type(fields.NaiveDateTime()) == "date"
        assert ResponseMaker.get_schema_type(fields.Decimal()) == "number"
        assert ResponseMaker.get_schema_type(fields.Email()) == "email"
        assert ResponseMaker.get_schema_type(fields.Float()) == "number"
        assert ResponseMaker.get_schema_type(fields.Int()) == "int"
        assert ResponseMaker.get_schema_type(fields.Integer()) == "int"
        assert ResponseMaker.get_schema_type(fields.Number()) == "number"
        assert ResponseMaker.get_schema_type(fields.Str()) == "string"
        assert ResponseMaker.get_schema_type(fields.String()) == "string"
        # Unsupported types, fallback to string
        assert ResponseMaker.get_schema_type(fields.URL()) == "string"
        assert ResponseMaker.get_schema_type(fields.Url()) == "string"
        assert ResponseMaker.get_schema_type(fields.UUID()) == "string"
        assert ResponseMaker.get_schema_type(fields.Constant("x")) == "string"
        assert ResponseMaker.get_schema_type(fields.Dict()) == "string"
        assert ResponseMaker.get_schema_type(fields.Field()) == "string"
        assert ResponseMaker.get_schema_type(fields.Function()) == "string"
        assert ResponseMaker.get_schema_type(fields.List(fields.Str())) == "string"
        assert ResponseMaker.get_schema_type(fields.Mapping()) == "string"
        assert ResponseMaker.get_schema_type(fields.Method()) == "string"
        assert ResponseMaker.get_schema_type(fields.Nested(fields.Str())) == "string"
        assert ResponseMaker.get_schema_type(fields.Raw()) == "string"
        assert ResponseMaker.get_schema_type(fields.TimeDelta()) == "string"

        assert not find_process("this-should-not-exist")
        assert find_process("restapi")
        assert find_process("dumb-init")
        # current process is not retrieved by find_process
        current_pid = os.getpid()
        process = psutil.Process(current_pid)
        assert not find_process(process.name())

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
        variables = Env.load_group(prefix)
        assert variables is not None
        assert isinstance(variables, dict)
        assert len(variables) == 3
        assert var2 in variables
        assert var3 not in variables
        assert var3.lower() in variables
        assert variables.get(var1.lower()) == val1
        assert variables.get(var2.lower()) == val2
        assert variables.get(var3.lower()) == val3

        start_timeout(15)
        try:
            wait_socket("invalid", 123, service_name="test")
            pytest.fail("wait_socket should be blocking!")
        except Timeout:
            pass

        s = Meta.get_celery_tasks(None)
        assert isinstance(s, dict)
        assert len(s) == 0

        # This is a valid package containing other packages... but no task will be found
        s = Meta.get_celery_tasks("restapi")
        assert isinstance(s, dict)
        assert len(s) == 0

        s = Meta.get_celery_tasks("this-should-not-exist")
        assert isinstance(s, dict)
        assert len(s) == 0

        s = Meta.get_classes_from_module("this-should-not-exist")
        assert isinstance(s, dict)
        assert len(s) == 0

        s = Meta.get_module_from_string("this-should-not-exist")
        assert s is None

        try:
            Meta.get_module_from_string(
                "this-should-not-exist", exit_on_fail=True,
            )
            pytest.fail("ModuleNotFoundError not raised")
        except ModuleNotFoundError:
            pass

        # This method is not very robust... but... let's test the current implementation
        # It basicaly return the first args if it is an instance of some classes
        s = Meta.get_self_reference_from_args()
        assert s is None
        s = Meta.get_self_reference_from_args("test")
        assert s == "test"

        s = Meta.import_models("this-should", "not-exist", exit_on_fail=False)
        assert isinstance(s, dict)
        assert len(s) == 0

        try:
            Meta.import_models("this-should", "not-exist", exit_on_fail=True)
            pytest.fail("SystemExit not raised")
        except SystemExit:
            pass

        # Check exit_on_fail default value
        try:
            Meta.import_models("this-should", "not-exist")
            pytest.fail("SystemExit not raised")
        except SystemExit:
            pass

        assert Meta.get_customizer_instance("invalid.path", "InvalidClass") is None
        assert (
            Meta.get_customizer_instance(
                "initialization.initialization", "InvalidClass"
            )
            is None
        )
        assert (
            Meta.get_customizer_instance("initialization.initialization", "Customizer")
            is not None
        )

        assert get_html_template("this-should-not-exist", {}) is None

        start_timeout(1)
        try:
            # This operation will be interrupted because slower than timeout
            time.sleep(2)
            pytest.fail("Operation not interrupted")
        except BaseException as e:
            assert str(e) == "Operation timeout: interrupted"

        start_timeout(1)
        try:
            stop_timeout()
            # This operation will not be interrupted
            time.sleep(2)
        except BaseException:
            pytest.fail("Operation interrupted")

        s = handle_log_output(None)
        assert isinstance(s, dict)
        assert len(s) == 0

        s = handle_log_output(" ")
        assert isinstance(s, dict)
        assert len(s) == 0

        # obfuscate_dict only accepts dict
        assert obfuscate_dict(None) is None
        assert obfuscate_dict(10) == 10
        assert obfuscate_dict(["x"]) == ["x"]
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

        assert hcodes.HTTP_CONTINUE == 100
        assert hcodes.HTTP_SWITCHING_PROTOCOLS == 101
        assert hcodes.HTTP_OK_BASIC == 200
        assert hcodes.HTTP_OK_CREATED == 201
        assert hcodes.HTTP_OK_ACCEPTED == 202
        assert hcodes.HTTP_OK_NORESPONSE == 204
        assert hcodes.HTTP_PARTIAL_CONTENT == 206
        assert hcodes.HTTP_MULTIPLE_CHOICES == 300
        assert hcodes.HTTP_FOUND == 302
        assert hcodes.HTTP_NOT_MODIFIED == 304
        assert hcodes.HTTP_TEMPORARY_REDIRECT == 307
        assert hcodes.HTTP_BAD_REQUEST == 400
        assert hcodes.HTTP_BAD_UNAUTHORIZED == 401
        assert hcodes.HTTP_BAD_FORBIDDEN == 403
        assert hcodes.HTTP_BAD_NOTFOUND == 404
        assert hcodes.HTTP_BAD_METHOD_NOT_ALLOWED == 405
        assert hcodes.HTTP_BAD_CONFLICT == 409
        assert hcodes.HTTP_BAD_RESOURCE == 410
        assert hcodes.HTTP_BAD_PAYLOAD_TOO_LARGE == 413
        assert hcodes.HTTP_BAD_RANGE_NOT_SATISFIABLE == 416
        assert hcodes.HTTP_SERVER_ERROR == 500
        assert hcodes.HTTP_NOT_IMPLEMENTED == 501
        assert hcodes.HTTP_SERVICE_UNAVAILABLE == 503
        assert hcodes.HTTP_INTERNAL_TIMEOUT == 504

        data = {"a": 1}
        assert mix(None, data) == data

        data1 = {"a": {"b": 1}, "c": 1}
        data2 = {"a": {"b": 2}}
        expected = {"a": {"b": 2}, "c": 1}

        assert mix(data1, data2) == expected

        data1 = {"a": {"b": 1}, "c": 1}
        data2 = {"a": None}
        # Cannot replace with an empty list
        assert mix(data1, data2) == data1

        data1 = {"a": [1, 2]}
        data2 = {"a": [3, 4]}
        expected = {"a": [1, 2, 3, 4]}

        assert mix(data1, data2) == expected

        meta = Uploader.get_file_metadata("invalid_file")
        assert isinstance(meta, dict)
        assert len(meta) == 0

        meta = Uploader.get_file_metadata("confs/projects_defaults.yaml")
        assert isinstance(meta, dict)
        assert len(meta) == 2
        assert "type" in meta
        assert "charset" in meta
        assert meta["type"] == "text/plain"
        assert meta["charset"] == "utf-8"

        # t = total_length
        # s = start
        # e = end
        t, s, e = Uploader.parse_content_range(None)
        assert t is None
        assert s is None
        assert e is None

        t, s, e = Uploader.parse_content_range("")
        assert t is None
        assert s is None
        assert e is None

        t, s, e = Uploader.parse_content_range("test")
        assert t is None
        assert s is None
        assert e is None

        t, s, e = Uploader.parse_content_range("test/test")
        assert t is None
        assert s is None
        assert e is None

        t, s, e = Uploader.parse_content_range("test/1000")
        assert t == 1000
        assert s == 0
        assert e == 1000

        t, s, e = Uploader.parse_content_range("bytes test/1000")
        assert t == 1000
        assert s == 0
        assert e == 1000

        t, s, e = Uploader.parse_content_range("bytes */1000")
        assert t == 1000
        assert s == 0
        assert e == 1000

        t, s, e = Uploader.parse_content_range("bytes 2-499/1000")
        assert t == 1000
        assert s == 2
        assert e == 500

        t, s, e = Uploader.parse_content_range("bytes 2-499*/1000")
        assert t == 1000
        assert s == 0
        assert e == 1000

        # Invalid file / path
        try:
            load_yaml_file("invalid", "path")
            pytest.fail("No exception raised")
        except AttributeError:
            pass

        try:
            load_yaml_file("invalid", "tests")
            pytest.fail("No exception raised")
        except AttributeError:
            pass

        # Valid path, but not in yaml format
        try:
            load_yaml_file("conftest.py", "tests")
            pytest.fail("No exception raised")
        except AttributeError:
            pass

        # File is empty
        f = tempfile.NamedTemporaryFile()
        try:
            load_yaml_file(f.name, ".")
            pytest.fail("No exception raised")
        except AttributeError:
            pass
        f.close()

        try:
            detector.get_connector(faker.pystr())
            pytest.fail("No exception raised")
        except ServiceUnavailable:
            pass
